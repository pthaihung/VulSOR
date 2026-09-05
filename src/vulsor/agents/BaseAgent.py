"""Base classes and runners for B2 semantic reconstruction agents."""

from __future__ import annotations

import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from vulsor.agents.LLMClient import SemanticLLMClient
from vulsor.agents.SemanticViews import (
    cross_view_links,
    list_of_dicts,
    validate_semantic_view,
)
from vulsor.agents.SemanticOverlay import build_semantic_graph_overlay
from vulsor.config import AgentLLMConfig


SCHEMA_VERSION = 2
SEMANTIC_AGENTS = ("state", "value", "execution", "operation")
LLM_VIEW_MAX_OBSERVATIONS = 6
FORBIDDEN_METADATA = {
    "target",
    "cwe",
    "cve",
    "cve_desc",
    "nvd_url",
    "pair_id",
    "commit_id",
    "commit_url",
    "commit_message",
    "side",
}


@dataclass(frozen=True)
class AgentRunResult:
    """Result metadata for one semantic agent run."""

    sample_id: str
    status: str
    output_path: str
    cache_hit: bool
    experiment_path: str | None = None
    agent: str | None = None
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_seconds: float = 0.0


def run_semantic_agent_for_manifest(
    manifest_path: Path,
    *,
    agent_name: str,
    brain_context_dir: Path = Path("brain_context"),
    sample_id: str | None = None,
    limit: int | None = None,
    force: bool = False,
    use_llm: bool = False,
    llm_config: AgentLLMConfig | None = None,
    experiments_dir: Path = Path("experiments"),
    parallel: bool = False,
    progress_callback: Callable[[AgentRunResult], None] | None = None,
) -> list[AgentRunResult]:
    """Run one B2 semantic agent for samples listed in a B1 manifest."""
    manifest = _read_json(manifest_path)
    samples = _list_of_dicts(manifest.get("samples"))

    if sample_id is not None:
        samples = [
            sample
            for sample in samples
            if sample.get("sample_id") == sample_id
        ]

    if limit is not None:
        samples = samples[:limit]

    agent = _agent_for_name(agent_name)
    results: list[AgentRunResult] = []

    for sample in samples:
        path = sample.get("path")

        if not isinstance(path, str):
            continue

        artifact_path = Path(path)
        try:
            result = agent.run(
                artifact_path,
                brain_context_dir=brain_context_dir,
                force=force,
                use_llm=use_llm,
                llm_config=llm_config,
                experiments_dir=experiments_dir,
            )
        except Exception as exc:
            result = AgentRunResult(
                sample_id=str(sample.get("sample_id", artifact_path.stem)),
                status="error",
                output_path=str(artifact_path),
                cache_hit=False,
                agent=agent_name,
                error=str(exc),
            )
        results.append(result)

    return results


def run_all_semantic_agents_for_manifest(
    manifest_path: Path,
    *,
    brain_context_dir: Path = Path("brain_context"),
    sample_id: str | None = None,
    limit: int | None = None,
    force: bool = False,
    use_llm: bool = False,
    llm_config: AgentLLMConfig | None = None,
    experiments_dir: Path = Path("experiments"),
    parallel: bool = False,
    progress_callback: Callable[[AgentRunResult], None] | None = None,
) -> list[AgentRunResult]:
    """Run all four B2 semantic agents."""
    manifest = _read_json(manifest_path)
    samples = _list_of_dicts(manifest.get("samples"))

    if sample_id is not None:
        samples = [
            sample
            for sample in samples
            if sample.get("sample_id") == sample_id
        ]

    if limit is not None:
        samples = samples[:limit]

    results: list[AgentRunResult] = []

    if parallel and len(SEMANTIC_AGENTS) > 1:
        tasks = []
        for agent_name in SEMANTIC_AGENTS:
            agent = _agent_for_name(agent_name)
            for sample in samples:
                path = sample.get("path")
                if isinstance(path, str):
                    tasks.append(
                        (agent_name, agent, Path(path))
                    )

        with ThreadPoolExecutor(max_workers=len(SEMANTIC_AGENTS)) as executor:
            future_to_index = {
                executor.submit(
                    agent.run,
                    path,
                    brain_context_dir=brain_context_dir,
                    force=force,
                    use_llm=use_llm,
                    llm_config=llm_config,
                    experiments_dir=experiments_dir,
                )
                : index
                for index, (_, agent, path) in enumerate(tasks)
            }
            completed_results: list[AgentRunResult | None] = [
                None
            ] * len(tasks)
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                agent_name, _, path = tasks[index]
                try:
                    result = future.result()
                except Exception as exc:
                    result = AgentRunResult(
                        sample_id=_sample_id_from_path(path),
                        status="error",
                        output_path=str(path),
                        cache_hit=False,
                        agent=agent_name,
                        error=str(exc),
                    )
                completed_results[index] = result
                if progress_callback is not None:
                    progress_callback(result)

        results.extend(
            result
            for result in completed_results
            if result is not None
        )
        return results

    for agent_name in SEMANTIC_AGENTS:
        agent_results = run_semantic_agent_for_manifest(
            manifest_path,
            agent_name=agent_name,
            brain_context_dir=brain_context_dir,
            sample_id=sample_id,
            limit=limit,
            force=force,
            use_llm=use_llm,
            llm_config=llm_config,
            experiments_dir=experiments_dir,
            progress_callback=progress_callback,
        )
        results.extend(agent_results)
        if progress_callback is not None:
            for result in agent_results:
                progress_callback(result)

    return results


def run_semantic_merge_for_manifest(
    manifest_path: Path,
    *,
    brain_context_dir: Path = Path("brain_context"),
    sample_id: str | None = None,
    limit: int | None = None,
    force: bool = False,
    experiments_dir: Path = Path("experiments"),
) -> list[AgentRunResult]:
    """Merge the four B2 semantic views into one artifact per sample."""
    manifest = _read_json(manifest_path)
    samples = _list_of_dicts(manifest.get("samples"))

    if sample_id is not None:
        samples = [
            sample
            for sample in samples
            if sample.get("sample_id") == sample_id
        ]

    if limit is not None:
        samples = samples[:limit]

    results: list[AgentRunResult] = []

    for sample in samples:
        path = sample.get("path")

        if not isinstance(path, str):
            continue

        results.append(
            merge_semantic_views(
                Path(path),
                brain_context_dir=brain_context_dir,
                force=force,
                experiments_dir=experiments_dir,
            )
        )

    return results


class BaseAgent:
    """Base class for B2 semantic agents.

    Subclasses own agent-specific semantics through `build_local_view`.
    This base class owns common lifecycle concerns: guide/prompt loading,
    cache keys, artifact paths, optional LLM calls, and boundary metadata.
    """

    agent_name = ""

    def __init__(self) -> None:
        if self.agent_name not in SEMANTIC_AGENTS:
            raise ValueError(f"unsupported semantic agent: {self.agent_name}")

    def run(
        self,
        artifact_path: Path,
        *,
        brain_context_dir: Path = Path("brain_context"),
        force: bool = False,
        use_llm: bool = False,
        llm_config: AgentLLMConfig | None = None,
        experiments_dir: Path = Path("experiments"),
    ) -> AgentRunResult:
        """Run one semantic agent for one B1 artifact."""
        started = perf_counter()
        llm_config = llm_config.for_agent(self.agent_name) if llm_config else None
        artifact_path = artifact_path.resolve()
        brain_context_dir = brain_context_dir.resolve()
        guide_path = brain_context_dir / "AGENT_GUIDE.md"
        prompt_path = self.prompt_path()
        artifact = _read_json(artifact_path)
        dataset = str(artifact["dataset"])
        split = str(artifact["split"])
        sample_id = str(artifact["sample_id"])
        output_dir = brain_context_dir / dataset / split / "agents" / sample_id
        output_path = output_dir / f"{self.agent_name}.json"
        experiment_path = (
            experiments_dir.resolve()
            / dataset
            / split
            / self.agent_name
            / f"{sample_id}.json"
        )
        cache_key = _cache_key(
            agent_name=self.agent_name,
            artifact_path=artifact_path,
            prompt_path=prompt_path,
            use_llm=use_llm,
            llm_config=llm_config,
        )

        if not force and output_path.is_file():
            cached = _read_json(output_path)

            if _cache_key_from_output(cached) == cache_key:
                if use_llm and not experiment_path.is_file():
                    experiment_path.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write_json(experiment_path, cached)
                runtime = _runtime_from_output(cached)

                return AgentRunResult(
                    sample_id=sample_id,
                    status=str(cached.get("status", "ok")),
                    output_path=str(output_path),
                    cache_hit=True,
                    experiment_path=str(experiment_path) if use_llm else None,
                    agent=self.agent_name,
                    error=_agent_output_error(cached),
                    input_tokens=int(runtime.get("input_tokens", 0)),
                    output_tokens=int(runtime.get("output_tokens", 0)),
                    elapsed_seconds=perf_counter() - started,
                )

        brain_view = None

        if use_llm and output_path.is_file():
            cached_brain = _read_json(output_path)
            brain_view = cached_brain.get(f"{self.agent_name}_view")

        output = self._build_output(
            artifact=artifact,
            artifact_path=artifact_path,
            guide_path=guide_path,
            prompt_path=prompt_path,
            cache_key=cache_key,
            use_llm=use_llm,
            llm_config=llm_config,
            brain_view=brain_view,
        )
        if use_llm and not output_path.is_file():
            brain_output = self._build_output(
                artifact=artifact,
                artifact_path=artifact_path,
                guide_path=guide_path,
                prompt_path=prompt_path,
                cache_key=cache_key,
                use_llm=False,
                llm_config=None,
                brain_view=None,
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(output_path, brain_output)
        elif not use_llm:
            output_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(output_path, output)

        if use_llm:
            experiment_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(experiment_path, output)
        runtime = _runtime_from_output(output)

        return AgentRunResult(
            sample_id=sample_id,
            status=str(output["status"]),
            output_path=str(output_path),
            cache_hit=False,
            experiment_path=str(experiment_path) if use_llm else None,
            agent=self.agent_name,
            error=_agent_output_error(output),
            input_tokens=int(runtime.get("input_tokens", 0)),
            output_tokens=int(runtime.get("output_tokens", 0)),
            elapsed_seconds=perf_counter() - started,
        )

    def _build_output(
        self,
        *,
        artifact: dict[str, Any],
        artifact_path: Path,
        guide_path: Path,
        prompt_path: Path,
        cache_key: str,
        use_llm: bool,
        llm_config: AgentLLMConfig | None,
        brain_view: dict[str, Any] | None,
    ) -> dict[str, Any]:
        sample = artifact.get("sample", {})
        analysis = sample.get("analysis", {})
        prompt_config = _read_json(prompt_path)
        local_view = self.build_local_view(artifact)
        view_validation = validate_semantic_view(self.agent_name, local_view)
        llm_result = None
        usage: dict[str, int] = {}

        if use_llm:
            client = SemanticLLMClient(llm_config or AgentLLMConfig())
            result = self._run_llm(
                client=client,
                prompt_config=prompt_config,
                artifact=artifact,
                artifact_path=artifact_path,
                brain_view=brain_view or local_view,
                llm_config=llm_config or AgentLLMConfig(),
            )
            parsed_json = _normalize_llm_payload(
                result.parsed_json,
                self.agent_name,
            )
            reasoning_validation = _validate_llm_reasoning(
                parsed_json,
                brain_view or local_view,
                _load_source_input(artifact, artifact_path),
            )
            llm_view_validation = _validate_llm_view_payload(
                parsed_json,
                self.agent_name,
            )
            usage = result.usage
            llm_result = {
                "status": result.status,
                "error": result.error,
                "output": parsed_json,
                "usage": result.usage,
                "view_validation": llm_view_validation,
                "reasoning_validation": reasoning_validation,
            }

        local_ok = view_validation["status"] == "ok"
        llm_ok = (
            llm_result is not None
            and llm_result["status"] == "ok"
            and llm_result["view_validation"]["status"] == "ok"
            and llm_result["reasoning_validation"]["status"] == "ok"
        )
        status = "ok" if local_ok and (not use_llm or llm_ok) else "error"
        runtime = {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        }

        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": "semantic_agent_output",
            "agent": self.agent_name,
            "status": status,
            "sample_id": artifact["sample_id"],
            "source_status": sample.get("status"),
            f"{self.agent_name}_view": local_view,
            "llm": {
                "enabled": use_llm,
                "provider": (llm_config or AgentLLMConfig()).provider,
                "model": (llm_config or AgentLLMConfig()).model,
                "result": llm_result,
            },
            "_meta": {
                "cache_key": cache_key,
                "input": {
                    "artifact": str(artifact_path),
                    "hash": _file_hash(artifact_path),
                },
                "guide": {
                    "path": str(guide_path),
                    "hash": _file_hash(guide_path),
                },
                "prompt": {
                    "path": str(prompt_path),
                    "hash": _file_hash(prompt_path),
                    "id": prompt_config.get("prompt_id"),
                    "version": prompt_config.get("version"),
                },
                "runtime": runtime,
                "view_validation": view_validation,
                "limitations": analysis.get("limitations", []),
                "boundary": {
                    "verdict": "not_allowed",
                    "cwe": "not_allowed",
                    "invented_facts": "not_allowed",
                    "llm_trust": (
                        "interpretation_only_not_evidence_or_verdict"
                    ),
                },
            },
        }

    def build_local_view(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Build the deterministic fallback semantic view."""
        raise NotImplementedError

    def prompt_path(self) -> Path:
        """Return the JSON prompt file for this agent."""
        return _prompt_path(self.agent_name)

    def _run_llm(
        self,
        *,
        client: SemanticLLMClient,
        prompt_config: dict[str, Any],
        artifact: dict[str, Any],
        artifact_path: Path,
        brain_view: dict[str, Any],
        llm_config: AgentLLMConfig,
    ):
        payload = _llm_payload(
            artifact,
            self.agent_name,
            brain_view=brain_view,
            artifact_path=artifact_path,
        )

        return client.complete_json(
            system_prompt=_prompt_text(prompt_config),
            user_payload=payload,
        )


def _prompt_text(prompt_config: dict[str, Any]) -> str:
    """Build the compact system prompt, including method and demonstrations."""
    sections = [str(prompt_config.get("system", ""))]
    method = prompt_config.get("reasoning_method")
    examples = prompt_config.get("few_shot_examples")

    if isinstance(method, str) and method:
        sections.append(f"Reasoning method: {method}")
    if isinstance(examples, list) and examples:
        sections.append(
            "Examples:\n"
            + json.dumps(examples, ensure_ascii=True, separators=(",", ":"))
        )

    sections.append(
        "Return only these two top-level keys. Do not repeat static brain rows "
        "such as variables, symbols, operations, control regions, resources, "
        "or metadata. Put the LLM contribution only in observations and "
        "evidence-linked reasoning_groups. Keep observations short; at most "
        f"{LLM_VIEW_MAX_OBSERVATIONS} items. source_excerpt must be copied "
        "from the supplied source text exactly; for split declarations, use "
        "the exact line containing the symbol or use unavailable.\n"
        "Required JSON shape:\n"
        + json.dumps(
            {
                prompt_config.get("view_key", "agent_view"): {
                    "observations": [
                        {
                            "claim": "one agent-specific observation",
                            "supporting_fact_ids": [
                                "exact fact id from the brain"
                            ],
                            "confidence": "high|medium|low",
                            "uncertainty": "uncertainty text or null",
                        }
                    ],
                    "summary": "concise agent-specific summary",
                },
                "reasoning_groups": [
                    {
                        "description": "short causal group summary",
                        "steps": [
                            {
                                "claim": "one grounded observation",
                                "derived_from": "fact id or fact ids",
                                "evidence": [
                                    {
                                        "fact_id": "exact fact id from the brain",
                                        "source_location": {
                                            "line": 1,
                                            "column": 1,
                                        },
                                        "source_excerpt": "exact source text or unavailable",
                                    }
                                ],
                                "confidence": "high|medium|low",
                                "uncertainty": "uncertainty text or null",
                            }
                        ],
                    }
                ],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )

    return "\n\n".join(sections)


def _agent_for_name(agent_name: str) -> BaseAgent:
    if agent_name == "state":
        from vulsor.agents.StateAgent import StateAgent

        return StateAgent()

    if agent_name == "value":
        from vulsor.agents.ValueAgent import ValueAgent

        return ValueAgent()

    if agent_name == "execution":
        from vulsor.agents.ExecutionAgent import ExecutionAgent

        return ExecutionAgent()

    if agent_name == "operation":
        from vulsor.agents.OperationAgent import OperationAgent

        return OperationAgent()

    raise ValueError(f"unsupported semantic agent: {agent_name}")


def merge_semantic_views(
    artifact_path: Path,
    *,
    brain_context_dir: Path = Path("brain_context"),
    force: bool = False,
    experiments_dir: Path = Path("experiments"),
) -> AgentRunResult:
    """Merge state/value/execution/operation artifacts for one sample."""
    artifact_path = artifact_path.resolve()
    brain_context_dir = brain_context_dir.resolve()
    experiments_dir = experiments_dir.resolve()
    artifact = _read_json(artifact_path)
    dataset = str(artifact["dataset"])
    split = str(artifact["split"])
    sample_id = str(artifact["sample_id"])
    agent_dir = brain_context_dir / dataset / split / "agents" / sample_id
    output_path = agent_dir / "agent_semantics.json"
    graph_path = agent_dir / "semantic_graph.json"
    input_paths = [agent_dir / f"{name}.json" for name in SEMANTIC_AGENTS]
    experiment_paths = [
        experiments_dir / dataset / split / name / f"{sample_id}.json"
        for name in SEMANTIC_AGENTS
    ]
    cache_key = _merge_cache_key(
        artifact_path,
        [*input_paths, *experiment_paths],
    )

    if not force and output_path.is_file():
        cached = _read_json(output_path)

        if _cache_key_from_output(cached) == cache_key:
            _write_semantic_graph_overlay(
                graph_path,
                cached,
                semantic_path=output_path,
                force=False,
            )
            return AgentRunResult(
                sample_id=sample_id,
                status=str(cached.get("status", "ok")),
                output_path=str(output_path),
                cache_hit=True,
                agent="merge",
            )

    views: dict[str, Any] = {}
    missing = []

    for agent_name, path in zip(SEMANTIC_AGENTS, input_paths):
        if not path.is_file():
            missing.append(
                {
                    "kind": "missing_agent_output",
                    "agent": agent_name,
                    "path": str(path),
                }
            )
            views[f"{agent_name}_view"] = None
            continue

        agent_output = _read_json(path)
        views[f"{agent_name}_view"] = agent_output.get(f"{agent_name}_view")

    sample = artifact.get("sample", {})
    analysis = sample.get("analysis", {})
    llm_semantics = _llm_semantics_for_sample(
        experiment_paths,
        agent_names=SEMANTIC_AGENTS,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "semantic_agent_merge",
        "agent": "merge",
        "status": "partial" if missing else "ok",
        "sample_id": sample_id,
        "agent_semantics": {
            "sample_id": sample_id,
            "source_artifact": str(artifact_path),
            "recovery_assumptions": analysis.get(
                "recovery_assumptions",
                [],
            ),
            **views,
            "cross_view_links": cross_view_links(views),
            "llm_semantics": llm_semantics,
            "missing_semantic_context": missing,
        },
        "_meta": {
            "cache_key": cache_key,
            "source_artifact": str(artifact_path),
            "limitations": analysis.get("limitations", []),
            "boundary": {
                "verdict": "not_allowed",
                "cwe": "not_allowed",
                "invented_facts": "not_allowed",
            },
        },
    }
    agent_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(output_path, payload)
    _write_semantic_graph_overlay(
        graph_path,
        payload,
        semantic_path=output_path,
        force=True,
    )

    return AgentRunResult(
        sample_id=sample_id,
        status=str(payload["status"]),
        output_path=str(output_path),
        cache_hit=False,
        agent="merge",
    )


def _write_semantic_graph_overlay(
    graph_path: Path,
    semantic_payload: dict[str, Any],
    *,
    semantic_path: Path,
    force: bool,
) -> None:
    """Write the per-sample semantic CPG overlay beside agent_semantics.json."""
    if not force and graph_path.is_file():
        cached = _read_json(graph_path)
        meta = cached.get("_meta")
        if isinstance(meta, dict) and meta.get("source_hash") == _file_hash(
            semantic_path
        ):
            return

    graph_payload = build_semantic_graph_overlay(semantic_payload)
    graph_payload["source_semantics"] = str(semantic_path)
    graph_payload["_meta"]["source_semantics"] = str(semantic_path)
    graph_payload["_meta"]["source_hash"] = _file_hash(semantic_path)
    _atomic_write_json(graph_path, graph_payload)


def _llm_semantics_for_sample(
    experiment_paths: list[Path],
    *,
    agent_names: tuple[str, ...],
) -> dict[str, Any]:
    """Collect validated LLM observations/reasoning from experiment outputs."""
    llm_semantics: dict[str, Any] = {}

    for agent_name, path in zip(agent_names, experiment_paths):
        if not path.is_file():
            continue

        output = _read_json(path)
        llm = output.get("llm")
        result = llm.get("result") if isinstance(llm, dict) else None
        if not isinstance(result, dict):
            continue

        if result.get("status") != "ok":
            continue

        view_validation = result.get("view_validation")
        reasoning_validation = result.get("reasoning_validation")
        if (
            isinstance(view_validation, dict)
            and view_validation.get("status") != "ok"
        ):
            continue
        if (
            isinstance(reasoning_validation, dict)
            and reasoning_validation.get("status") != "ok"
        ):
            continue

        parsed = result.get("output")
        if not isinstance(parsed, dict):
            continue

        view = parsed.get(f"{agent_name}_view")
        observations = []
        summary = None
        if isinstance(view, dict):
            observations = list_of_dicts(view.get("observations"))
            summary = view.get("summary")

        llm_semantics[agent_name] = {
            "source": str(path),
            "provider": llm.get("provider") if isinstance(llm, dict) else None,
            "model": llm.get("model") if isinstance(llm, dict) else None,
            "observations": observations,
            "summary": summary if isinstance(summary, str) else None,
            "reasoning_groups": list_of_dicts(
                parsed.get("reasoning_groups")
            ),
            "usage": result.get("usage") or {},
            "view_validation": view_validation or {},
            "reasoning_validation": reasoning_validation or {},
        }

    return llm_semantics


def _facts_and_analysis(
    artifact: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    sample = artifact.get("sample", {})
    result = sample.get("result", {})
    analysis = sample.get("analysis", {})

    return result.get("program_facts") or {}, analysis


def _llm_payload(
    artifact: dict[str, Any],
    agent_name: str,
    *,
    brain_view: dict[str, Any] | None = None,
    artifact_path: Path | None = None,
) -> dict[str, Any]:
    sample = artifact.get("sample", {})
    analysis = sample.get("analysis", {})
    result = sample.get("result", {})

    source = _load_source_input(artifact, artifact_path)
    source_context = _source_windows(source, brain_view or {})

    return {
        "agent": agent_name,
        "sample_id": artifact.get("sample_id"),
        "source": source_context,
        "reading_order": [
            "brain_context/{dataset}/{split}/agents/{sample_id}/{agent}.json",
            "data/{dataset}_clean/inputs/{split}.jsonl",
        ],
        "brain": _compact_brain(brain_view or {}),
        "brain_contract": (
            "This is the filtered context produced by the same agent in phase 1. "
            "Reason only from this brain and the supplied source."
        ),
        "limitations": analysis.get("limitations") or [],
    }


def _load_source_input(
    artifact: dict[str, Any],
    artifact_path: Path | None,
) -> dict[str, Any]:
    """Load the exact source record used to create a B1 artifact."""
    sample_id = artifact.get("sample_id")
    dataset = artifact.get("dataset")
    split = artifact.get("split")

    if (
        not isinstance(sample_id, str)
        or not isinstance(dataset, str)
        or not isinstance(split, str)
    ):
        return {
            "available": False,
            "reason": "artifact is missing dataset, split, or sample_id",
        }

    roots = []

    if artifact_path is not None:
        workspace_root = artifact_path.resolve()
        for _ in range(4):
            workspace_root = workspace_root.parent
        roots.append(workspace_root)

    roots.append(Path.cwd())
    input_paths = []

    for root in roots:
        input_paths.extend(
            [
                root / "data" / f"{dataset}_clean" / "inputs" / f"{split}.jsonl",
                root / "data" / dataset / "inputs" / f"{split}.jsonl",
            ]
        )

    for input_path in input_paths:
        if not input_path.is_file():
            continue

        with input_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if record.get("sample_id") != sample_id:
                    continue

                code = record.get("code")
                if not isinstance(code, str):
                    break

                return {
                    "available": True,
                    "path": str(input_path),
                    "sample_id": sample_id,
                    "code": code,
                }

    return {
        "available": False,
        "sample_id": sample_id,
        "reason": "source record was not found in dataset inputs",
    }


def _compact_brain(value: Any) -> Any:
    """Remove duplicated presentation fields without dropping fact identity."""
    if isinstance(value, dict):
        compact = {}
        for key, item in value.items():
            if key in {"definition_locations", "use_locations"}:
                continue
            compact[key] = _compact_brain(item)
        return compact

    if isinstance(value, list):
        return [_compact_brain(item) for item in value]

    return value


def _source_windows(
    source: dict[str, Any],
    brain: dict[str, Any],
    *,
    radius: int = 4,
    fallback_lines: int = 80,
    max_lines: int = 160,
) -> dict[str, Any]:
    """Return source lines near brain evidence locations for the LLM input."""
    code = source.get("code") if source.get("available") else None
    if not isinstance(code, str):
        return {"available": False, "reason": source.get("reason", "source unavailable")}

    lines = code.splitlines()
    locations = sorted(_line_numbers(brain))
    requested_lines = set(locations)
    selected: set[int] = set()

    for line in locations:
        selected.update(range(max(1, line - radius), min(len(lines), line + radius) + 1))

    if not selected:
        selected.update(range(1, min(len(lines), fallback_lines) + 1))
    elif len(selected) > max_lines:
        selected = set(sorted(selected)[:max_lines])

    missing_lines = sorted(requested_lines - selected)

    windows = []
    for start, end in _contiguous_ranges(sorted(selected)):
        windows.append(
            {
                "start_line": start,
                "end_line": end,
                "code": "\n".join(lines[start - 1:end]),
            }
        )

    return {
        "available": True,
        "path": source.get("path"),
        "sample_id": source.get("sample_id"),
        "context_complete": not missing_lines and len(selected) >= len(lines),
        "requested_source_lines": sorted(requested_lines),
        "missing_source_lines": missing_lines,
        "windows": windows,
    }


def _line_numbers(value: Any) -> set[int]:
    numbers: set[int] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"line", "start_line", "end_line"} and isinstance(item, int):
                if key in {"line", "start_line", "end_line"}:
                    numbers.add(item)
            elif isinstance(item, str):
                numbers.update(_line_numbers_from_fact_id(item))
            else:
                numbers.update(_line_numbers(item))
    elif isinstance(value, list):
        for item in value:
            numbers.update(_line_numbers(item))
    elif isinstance(value, str):
        numbers.update(_line_numbers_from_fact_id(value))
    return {line for line in numbers if line > 0}


def _line_numbers_from_fact_id(value: str) -> set[int]:
    match = re.search(r":(?P<line>\d+):\d+(?::|$)", value)
    if not match:
        return set()

    return {int(match.group("line"))}


def _contiguous_ranges(numbers: list[int]) -> list[tuple[int, int]]:
    if not numbers:
        return []
    ranges = []
    start = previous = numbers[0]
    for number in numbers[1:]:
        if number != previous + 1:
            ranges.append((start, previous))
            start = number
        previous = number
    ranges.append((start, previous))
    return ranges


def _strip_forbidden(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_forbidden(item)
            for key, item in value.items()
            if key not in FORBIDDEN_METADATA
        }

    if isinstance(value, list):
        return [_strip_forbidden(item) for item in value]

    return value


def _tool_requests(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    requests = payload.get("tool_requests")

    if not isinstance(requests, list):
        return []

    clean_requests = []

    for request in requests:
        if not isinstance(request, dict):
            continue

        tool = request.get("tool")

        if not isinstance(tool, str) or not tool:
            continue

        arguments = request.get("arguments")

        if arguments is not None and not isinstance(arguments, dict):
            arguments = {}

        clean_requests.append(
            {
                "tool": tool,
                "arguments": arguments or {},
            }
        )

    return clean_requests


def _normalize_llm_payload(
    payload: dict[str, Any] | None,
    agent_name: str,
) -> dict[str, Any] | None:
    """Normalize near-contract LLM JSON before evidence validation."""
    if not isinstance(payload, dict):
        return payload

    raw = json.loads(json.dumps(payload))
    view_key = f"{agent_name}_view"
    normalized: dict[str, Any] = {}

    if view_key in raw:
        normalized[view_key] = _normalize_llm_view(raw.get(view_key))

    groups = raw.get("reasoning_groups")

    if not isinstance(groups, list):
        return normalized

    normalized["reasoning_groups"] = groups
    view_steps = _llm_view_steps(normalized, agent_name)

    for group in groups:
        if not isinstance(group, dict):
            continue

        if not isinstance(group.get("description"), str):
            reasoning = group.get("reasoning")
            if isinstance(reasoning, str):
                group["description"] = reasoning
            else:
                group["description"] = "grounded semantic observations"

        steps = group.get("steps")
        if not isinstance(steps, list):
            steps = _steps_for_group(group, view_steps)
            group["steps"] = steps

        for step in steps:
            if isinstance(step, dict):
                _normalize_llm_step(step)

    return normalized


def _normalize_llm_view(view: Any) -> dict[str, Any] | list[Any] | Any:
    """Keep only the lean LLM view columns used by B2."""
    if isinstance(view, str):
        return view

    if isinstance(view, list):
        return {
            "observations": _normalize_llm_observations(view),
            "summary": "LLM observations",
        }

    if not isinstance(view, dict):
        return view

    observations = view.get("observations")
    if not isinstance(observations, list):
        observations = [view] if _looks_like_llm_observation(view) else []

    summary = view.get("summary")
    return {
        "observations": _normalize_llm_observations(observations),
        "summary": summary if isinstance(summary, str) else "LLM observations",
    }


def _normalize_llm_observations(items: list[Any]) -> list[dict[str, Any]]:
    observations = []

    for item in items[:LLM_VIEW_MAX_OBSERVATIONS]:
        if not isinstance(item, dict):
            continue

        fact_ids = item.get("supporting_fact_ids")
        if not isinstance(fact_ids, list):
            derived = item.get("derived_from") or item.get("fact_id")
            fact_ids = derived if isinstance(derived, list) else [derived]
        fact_ids = [
            fact_id
            for fact_id in fact_ids
            if isinstance(fact_id, str)
        ]

        observations.append(
            {
                "claim": (
                    item.get("claim")
                    if isinstance(item.get("claim"), str)
                    else item.get("summary")
                    if isinstance(item.get("summary"), str)
                    else "grounded observation"
                ),
                "supporting_fact_ids": fact_ids,
                "confidence": item.get("confidence")
                if item.get("confidence") in {"high", "medium", "low"}
                else "low",
                "uncertainty": item.get("uncertainty")
                if isinstance(item.get("uncertainty"), str)
                or item.get("uncertainty") is None
                else str(item.get("uncertainty")),
            }
        )

    return observations


def _looks_like_llm_observation(value: dict[str, Any]) -> bool:
    return any(
        key in value
        for key in (
            "claim",
            "summary",
            "supporting_fact_ids",
            "derived_from",
            "fact_id",
        )
    )


def _llm_view_steps(
    payload: dict[str, Any],
    agent_name: str,
) -> list[dict[str, Any]]:
    view = payload.get(f"{agent_name}_view")
    if isinstance(view, dict):
        view = view.get("observations")

    if not isinstance(view, list):
        return []

    steps = []
    for item in view:
        if not isinstance(item, dict):
            continue

        step = {
            "claim": item.get("claim") or item.get("summary") or "grounded observation",
            "derived_from": item.get("derived_from") or item.get("fact_id"),
            "evidence": item.get("evidence"),
            "confidence": item.get("confidence"),
            "uncertainty": item.get("uncertainty"),
        }
        _normalize_llm_step(step)
        steps.append(step)

    return steps


def _steps_for_group(
    group: dict[str, Any],
    view_steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    fact_ids = set()
    for key in ("operations", "facts", "fact_ids"):
        values = group.get(key)
        if isinstance(values, list):
            fact_ids.update(
                fact_id
                for fact_id in values
                if isinstance(fact_id, str)
            )

    if not fact_ids:
        return list(view_steps)

    selected = []
    for step in view_steps:
        derived = step.get("derived_from")
        if derived in fact_ids:
            selected.append(step)
            continue

        evidence = step.get("evidence")
        if not isinstance(evidence, list):
            continue

        if any(item.get("fact_id") in fact_ids for item in evidence if isinstance(item, dict)):
            selected.append(step)

    return selected


def _normalize_llm_step(step: dict[str, Any]) -> None:
    if not isinstance(step.get("claim"), str):
        step["claim"] = "grounded observation"

    evidence = step.get("evidence")
    if isinstance(evidence, dict):
        evidence_items = [evidence]
    elif isinstance(evidence, list):
        evidence_items = evidence
    else:
        evidence_items = []

    normalized_evidence = []
    for item in evidence_items:
        if not isinstance(item, dict):
            normalized_evidence.append(item)
            continue

        if "source_location" not in item:
            item["source_location"] = _parse_source_location(item.get("location"))

        if "source_excerpt" not in item and "excerpt" in item:
            item["source_excerpt"] = item.get("excerpt")

        normalized_evidence.append(item)

    step["evidence"] = normalized_evidence


def _parse_source_location(value: Any) -> dict[str, int | None]:
    if isinstance(value, dict):
        line = value.get("line")
        column = value.get("column")
        return {
            "line": line if isinstance(line, int) else None,
            "column": column if isinstance(column, int) else None,
        }

    if not isinstance(value, str):
        return {"line": None, "column": None}

    line_match = re.search(r"\bline\s+(?P<line>\d+)\b", value, re.IGNORECASE)
    column_match = re.search(
        r"\bcolumn\s+(?P<column>\d+)\b",
        value,
        re.IGNORECASE,
    )

    return {
        "line": int(line_match.group("line")) if line_match else None,
        "column": int(column_match.group("column")) if column_match else None,
    }


def _agent_output_error(output: dict[str, Any]) -> str | None:
    if output.get("status") != "error":
        return None

    meta = output.get("_meta")
    validation = meta.get("view_validation") if isinstance(meta, dict) else None
    if isinstance(validation, dict) and validation.get("status") == "error":
        issues = validation.get("issues")
        if isinstance(issues, list):
            return f"semantic view schema validation failed: {len(issues)} issue(s)"
        return "semantic view schema validation failed"

    llm = output.get("llm")
    result = llm.get("result") if isinstance(llm, dict) else None
    if not isinstance(result, dict):
        return "agent output status is error"

    llm_error = result.get("error")
    if isinstance(llm_error, str) and llm_error:
        return f"LLM API error: {llm_error}"

    validation = result.get("reasoning_validation")
    if isinstance(validation, dict):
        status = validation.get("status")
        reason = validation.get("reason")
        issues = validation.get("issues")

        if isinstance(reason, str) and reason:
            return f"LLM reasoning validation {status}: {reason}"

        if isinstance(issues, list) and issues:
            return f"LLM reasoning validation {status}: {len(issues)} issue(s)"

        if isinstance(status, str) and status != "ok":
            return f"LLM reasoning validation {status}"

    validation = result.get("view_validation")
    if isinstance(validation, dict):
        status = validation.get("status")
        reason = validation.get("reason")
        issues = validation.get("issues")

        if isinstance(reason, str) and reason:
            return f"LLM view validation {status}: {reason}"

        if isinstance(issues, list) and issues:
            return f"LLM view validation {status}: {len(issues)} issue(s)"

        if isinstance(status, str) and status != "ok":
            return f"LLM view validation {status}"

    llm_status = result.get("status")
    if isinstance(llm_status, str) and llm_status != "ok":
        return f"LLM result status: {llm_status}"

    return "agent output status is error"


def _cache_key_from_output(output: dict[str, Any]) -> str | None:
    cache_key = output.get("cache_key")
    if isinstance(cache_key, str):
        return cache_key

    meta = output.get("_meta")
    if isinstance(meta, dict):
        cache_key = meta.get("cache_key")
        if isinstance(cache_key, str):
            return cache_key

    return None


def _runtime_from_output(output: dict[str, Any]) -> dict[str, int]:
    runtime = output.get("runtime")
    if isinstance(runtime, dict):
        return runtime

    meta = output.get("_meta")
    if isinstance(meta, dict):
        runtime = meta.get("runtime")
        if isinstance(runtime, dict):
            return runtime

    return {}


def _validate_llm_view_payload(
    payload: dict[str, Any] | None,
    agent_name: str,
) -> dict[str, Any]:
    """Validate the agent-specific view returned by the LLM."""
    if not isinstance(payload, dict):
        return {
            "status": "unsupported",
            "reason": "LLM output is not a JSON object",
            "issues": [],
        }

    view_key = f"{agent_name}_view"
    if view_key not in payload:
        return {
            "status": "unsupported",
            "reason": f"{view_key} is missing",
            "issues": [
                {
                    "path": view_key,
                    "reason": "required key is missing",
                }
            ],
        }

    view = payload.get(view_key)
    issues: list[dict[str, Any]] = []

    if isinstance(view, str):
        issues.append(
            {
                "path": view_key,
                "reason": "must be structured JSON, not a string",
            }
        )
    elif isinstance(view, dict):
        observations = view.get("observations")
        if observations is None:
            issues.append(
                {
                    "path": f"{view_key}.observations",
                    "reason": "required key is missing",
                }
            )
        elif not isinstance(observations, list):
            issues.append(
                {
                    "path": f"{view_key}.observations",
                    "reason": "must be a list",
                }
            )
        summary = view.get("summary")
        if summary is not None and not isinstance(summary, str):
            issues.append(
                {
                    "path": f"{view_key}.summary",
                    "reason": "must be a string",
                }
            )
        _validate_llm_no_forbidden_keys(view, view_key, issues)
    elif isinstance(view, list):
        _validate_llm_no_forbidden_keys(view, view_key, issues)
    else:
        issues.append(
            {
                "path": view_key,
                "reason": "must be an object or list",
            }
        )

    return {
        "status": "ok" if not issues else "unsupported",
        "issues": issues,
    }


def _validate_llm_no_forbidden_keys(
    value: Any,
    path: str,
    issues: list[dict[str, Any]],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_METADATA:
                issues.append(
                    {
                        "path": f"{path}.{key}",
                        "reason": "forbidden metadata/verdict field in LLM view",
                    }
                )
            _validate_llm_no_forbidden_keys(item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_llm_no_forbidden_keys(item, f"{path}[{index}]", issues)


def _validate_llm_reasoning(
    payload: dict[str, Any] | None,
    brain_view: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    """Validate reasoning evidence against the agent brain and source."""
    if not isinstance(payload, dict):
        return {
            "status": "unsupported",
            "reason": "LLM output is not a JSON object",
            "checked_steps": 0,
            "unsupported_steps": 0,
        }

    groups = payload.get("reasoning_groups")
    if not isinstance(groups, list):
        return {
            "status": "unsupported",
            "reason": "reasoning_groups is missing or is not a list",
            "checked_steps": 0,
            "unsupported_steps": 0,
        }

    fact_ids = _collect_fact_ids(brain_view)
    source_code = source.get("code") if source.get("available") else None
    checked_steps = 0
    unsupported_steps = 0
    issues: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for group_index, group in enumerate(groups):
        if not isinstance(group, dict):
            unsupported_steps += 1
            issues.append({"group": group_index, "reason": "group is not an object"})
            continue

        if not isinstance(group.get("description"), str):
            issues.append({"group": group_index, "reason": "missing description"})

        steps = group.get("steps")
        if not isinstance(steps, list):
            unsupported_steps += 1
            issues.append({"group": group_index, "reason": "steps is missing or is not a list"})
            continue

        for step_index, step in enumerate(steps):
            checked_steps += 1
            step_issues = []

            if not isinstance(step, dict):
                step_issues.append("step is not an object")
            else:
                evidence = step.get("evidence")
                if not isinstance(evidence, list) or not evidence:
                    step_issues.append("missing evidence")
                else:
                    for evidence_item in evidence:
                        if not isinstance(evidence_item, dict):
                            step_issues.append("evidence item is not an object")
                            continue

                        fact_id = evidence_item.get("fact_id")
                        if fact_id not in fact_ids:
                            step_issues.append(f"unknown fact_id: {fact_id!r}")

                        location = evidence_item.get("source_location")
                        line_number = (
                            location.get("line")
                            if isinstance(location, dict)
                            else None
                        )
                        excerpt = evidence_item.get("source_excerpt")
                        if excerpt != "unavailable":
                            if not isinstance(excerpt, str) or not source_code:
                                step_issues.append("source_excerpt is not present in source input")
                            else:
                                source_lines = source_code.splitlines()
                                excerpt_compact = _compact_text(excerpt)
                                source_compact = _compact_text(source_code)

                                if not isinstance(line_number, int):
                                    if (
                                        excerpt_compact
                                        and excerpt_compact in source_compact
                                    ):
                                        warnings.append(
                                            {
                                                "group": group_index,
                                                "step": step_index,
                                                "reason": (
                                                    "source_location.line is missing "
                                                    "but source_excerpt is present"
                                                ),
                                            }
                                        )
                                    else:
                                        step_issues.append(
                                            "source_location.line is missing"
                                        )
                                elif not 1 <= line_number <= len(source_lines):
                                    step_issues.append(
                                        "source_location.line is outside source input"
                                    )
                                else:
                                    line_text = source_lines[line_number - 1]
                                    line_compact = _compact_text(line_text)
                                    if (
                                        excerpt_compact
                                        and excerpt_compact not in source_compact
                                    ):
                                        if _line_mentions_fact_symbol(
                                            line_text,
                                            fact_id,
                                        ):
                                            warnings.append(
                                                {
                                                    "group": group_index,
                                                    "step": step_index,
                                                    "reason": (
                                                        "source_excerpt is not exact, "
                                                        "but fact symbol appears at "
                                                        "the reported line"
                                                    ),
                                                }
                                            )
                                        else:
                                            step_issues.append(
                                                "source_excerpt is not present in source input"
                                            )
                                    elif (
                                        excerpt_compact
                                        and excerpt_compact not in line_compact
                                    ):
                                        warnings.append(
                                            {
                                                "group": group_index,
                                                "step": step_index,
                                                "reason": (
                                                    "source_excerpt is present in source "
                                                    "but not at the reported line"
                                                ),
                                            }
                                        )

            if step_issues:
                unsupported_steps += 1
                issues.append(
                    {
                        "group": group_index,
                        "step": step_index,
                        "reasons": step_issues,
                    }
                )

    return {
        "status": "ok" if not issues else "unsupported",
        "checked_steps": checked_steps,
        "unsupported_steps": unsupported_steps,
        "issues": issues,
        "warnings": warnings,
    }


def _compact_text(value: str) -> str:
    return " ".join(value.split())


def _line_mentions_fact_symbol(line_text: str, fact_id: Any) -> bool:
    if not isinstance(fact_id, str):
        return False

    parts = fact_id.split(":")
    if len(parts) < 2:
        return False

    symbol = parts[1]
    if not symbol or symbol == "None":
        return False

    return re.search(rf"\b{re.escape(symbol)}\b", line_text) is not None


def _collect_fact_ids(value: Any) -> set[str]:
    fact_ids: set[str] = set()

    if isinstance(value, dict):
        for key, item in value.items():
            if key == "id" or key.endswith("_id"):
                if isinstance(item, str):
                    fact_ids.add(item)
            elif key == "supporting_fact_ids" and isinstance(item, list):
                fact_ids.update(
                    fact_id
                    for fact_id in item
                    if isinstance(fact_id, str)
                )
            fact_ids.update(_collect_fact_ids(item))

    elif isinstance(value, list):
        for item in value:
            fact_ids.update(_collect_fact_ids(item))

    return fact_ids


def _sample_id_from_path(path: Path) -> str:
    """Use the artifact filename as a stable fallback sample identifier."""
    return path.stem


def _prompt_path(agent_name: str) -> Path:
    return Path(__file__).resolve().parent / "prompts" / f"{agent_name}.json"


def _cache_key(
    *,
    agent_name: str,
    artifact_path: Path,
    prompt_path: Path,
    use_llm: bool,
    llm_config: AgentLLMConfig | None,
) -> str:
    digest = hashlib.sha256()
    digest.update(f"agent={agent_name}\n".encode("utf-8"))
    digest.update(f"schema={SCHEMA_VERSION}\n".encode("utf-8"))
    digest.update(f"use_llm={use_llm}\n".encode("utf-8"))

    if use_llm:
        config = llm_config or AgentLLMConfig()
        digest.update(f"llm_provider={config.provider}\n".encode("utf-8"))
        digest.update(f"llm_base_url={config.base_url}\n".encode("utf-8"))
        digest.update(f"llm_model={config.model}\n".encode("utf-8"))
        digest.update(f"llm_temperature={config.temperature}\n".encode("utf-8"))
        digest.update(f"llm_max_tool_rounds={config.max_tool_rounds}\n".encode("utf-8"))
        digest.update(
            f"llm_extra_headers={json.dumps(config.extra_headers, sort_keys=True)}\n".encode(
                "utf-8"
            )
        )
        digest.update(
            f"llm_allowed_tools={','.join(config.allowed_tools)}\n".encode("utf-8")
        )

    for path in (artifact_path, prompt_path):
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"")
        digest.update(b"\0")

    return digest.hexdigest()


def _merge_cache_key(artifact_path: Path, input_paths: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(f"agent=merge\nschema={SCHEMA_VERSION}\n".encode("utf-8"))

    for path in [artifact_path, *input_paths]:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"")
        digest.update(b"\0")

    return digest.hexdigest()


def _file_hash(path: Path) -> str | None:
    if not path.is_file():
        return None

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, path)


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return list_of_dicts(value)
