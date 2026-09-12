from __future__ import annotations

import argparse
import getpass
import os
import random
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from src.agents.LLMClient import mask_api_key, normalize_api_key
from src.agents.Pipeline import STAGE_LABELS, VulSORPipeline, count_lines, read_json_file

try:
    from rich.console import Console as RichConsole
    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
except ImportError:  # pragma: no cover - rich is optional for plain log fallback
    RichConsole = None
    Progress = None
    BarColumn = None
    TaskProgressColumn = None
    TextColumn = None
    TimeElapsedColumn = None
    TimeRemainingColumn = None

try:
    from tqdm import tqdm as Tqdm
except ImportError:  # pragma: no cover - tqdm is optional
    Tqdm = None


RUN_PIPELINE_LABEL = "run-pipeline"


def sample_run_label(stage: int, *, exact_stage: bool) -> str:
    if exact_stage:
        return STAGE_LABELS[stage]
    return RUN_PIPELINE_LABEL


class Console:
    RESET = "\033[0m"
    DIM = "\033[90m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"

    def __init__(self) -> None:
        self.enabled = sys.stdout.isatty()

    def color(self, text: str, color: str) -> str:
        if not self.enabled:
            return text
        return f"{color}{text}{self.RESET}"

    def print(self, text: str = "", color: str | None = None) -> None:
        print(self.color(text, color) if color else text, flush=True)

    def clear(self) -> None:
        if self.enabled:
            print("\033[2J\033[H", end="", flush=True)

    def centered(self, text: str, color: str | None = None) -> None:
        width = terminal_width()
        for line in text.splitlines():
            rendered = line.center(width) if len(line) < width else line
            self.print(rendered, color)


BANNER = r"""
██████╗ ██████╗ ███████╗███╗   ██╗    ██╗   ██╗██╗   ██╗██╗      ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██║   ██║██║   ██║██║      ██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██║   ██║██║   ██║██║      ███████╗██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ╚██╗ ██╔╝██║   ██║██║      ╚════██║██║   ██║██╔══██╗
╚██████╔╝██║     ███████╗██║ ╚████║     ╚████╔╝ ╚██████╔╝███████╗ ███████║╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝      ╚═══╝   ╚═════╝ ╚══════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"""


def run_interactive(project_root: Path) -> None:
    console = Console()
    console.clear()
    print_banner(console)
    console.print()

    dataset = choose_dataset(console)
    split = choose_option(
        console,
        title="Dataset split",
        options=[
            ("test", "default", "Use the test split."),
            ("train", "suggestion", "Use the training split."),
            ("valid", "suggestion", "Use the validation split."),
        ],
        default="test",
        allow_custom=False,
    )
    use_llm = choose_bool(
        console,
        "Use LLM API",
        default=True,
        yes_help_text="Call the configured LLM provider and run the real agent pipeline.",
        no_help_text="Render prompts locally without calling the configured LLM provider.",
    )
    dry_run = not use_llm
    if use_llm:
        prompt_api_key(console)
    overwrite = choose_bool(
        console,
        "Overwrite selected split outputs",
        default=False,
        yes_help_text="Clear previous stage outputs for this split before running.",
        no_help_text="Keep existing stage outputs and reuse them when applicable.",
    )
    cache_policy = choose_cache_policy(console) if use_llm else "disabled"
    pipeline = VulSORPipeline(
        project_root=project_root,
        split=split,
        dry_run=dry_run,
        overwrite=overwrite,
        no_cache=(cache_policy == "disabled"),
        refresh_cache=(cache_policy == "refresh"),
    )
    console.print(f"Selected dataset: {dataset}", Console.DIM)

    while True:
        console.print()
        action = choose_option(
            console,
            title="What would you like to do?",
            options=[
                ("inspect", "suggestion", "Show sample metadata and stage artifact status."),
                ("run-pipeline", "default", "Execute the pipeline up to a selected stage."),
                ("run-stage", "suggestion", "Run only one stage; previous stage outputs must already exist."),
                ("status", "suggestion", "Print stage status for selected samples."),
                ("exit", "suggestion", "Leave the interactive menu."),
            ],
            default="run-pipeline",
            allow_custom=False,
        )
        if action == "exit":
            return
        try:
            if action == "inspect":
                samples = prompt_samples(console, pipeline, default="0")
                inspect_samples(console, pipeline, samples)
                pause()
                continue
            if action == "status":
                samples = prompt_samples(console, pipeline, default="0-10")
                print_status(console, pipeline, samples)
                pause()
                continue

            stage = choose_stage(console, allow_all=(action == "run-pipeline"))
            samples = prompt_samples(console, pipeline, default="0")
            if action == "run-stage":
                run_samples_exact_stage(console, pipeline, samples, stage)
            else:
                run_samples_to_stage(console, pipeline, samples, stage)
            pause()
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            console.print(str(exc), Console.RED)
            pause()


def print_banner(console: Console) -> None:
    console.centered(BANNER.strip("\n"), Console.PURPLE)
    console.centered("Semantic Vulnerability Research", Console.DIM)
    console.centered("C / C++  -  Semantic Obligations  -  Verification", Console.DIM)


def terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(120, 30)).columns


def choose_dataset(console: Console) -> str:
    return choose_option(
        console,
        title="Dataset",
        options=[
            ("primevul_clean", "default", "Use the configured PrimeVul clean dataset."),
            ("primevul_raw", "suggestion", "Raw metadata dataset; not used by the current staged pipeline."),
        ],
        default="primevul_clean",
        allow_custom=True,
    )


def choose_stage(console: Console, allow_all: bool = False) -> int:
    final_stage = max(STAGE_LABELS)
    options = [
        ("1", "suggestion", "Build semantic model from source code."),
        ("2", "suggestion", "Build obligations from Stage 1 output."),
        (str(final_stage), "suggestion" if allow_all else "default", "Adjudicate obligations and produce final verdict."),
    ]
    default = str(final_stage)
    if allow_all:
        options.append(("all", "default", f"Run every stage through Stage {final_stage}."))
        default = "all"
    value = choose_option(
        console,
        title="Target stage",
        options=options,
        default=default,
        allow_custom=False,
    )
    if value == "all":
        return final_stage
    return int(value)


def choose_bool(
    console: Console,
    title: str,
    default: bool,
    yes_help_text: str,
    no_help_text: str,
) -> bool:
    default_value = "yes" if default else "no"
    value = choose_option(
        console,
        title=title,
        options=[
            ("yes", "default" if default else "suggestion", yes_help_text),
            ("no", "default" if not default else "suggestion", no_help_text),
        ],
        default=default_value,
        allow_custom=False,
    )
    return value == "yes"


def choose_cache_policy(console: Console) -> str:
    return choose_option(
        console,
        title="LLM cache",
        options=[
            ("use", "default", "Reuse existing LLM responses and save new responses."),
            ("disabled", "suggestion", "Do not read or write the LLM response cache."),
            ("refresh", "suggestion", "Clear existing LLM responses first, then save new responses."),
        ],
        default="use",
        allow_custom=False,
    )


def prompt_api_key(console: Console) -> None:
    env_name = "DEEPSEEK_API_KEY"
    existing = normalize_api_key(os.environ.get(env_name, ""))
    if existing:
        os.environ[env_name] = existing
    console.print("LLM API key", Console.BOLD)
    if existing:
        console.print(f"{env_name}: existing key found ({mask_api_key(existing)}). Press Enter to keep it.", Console.DIM)
    else:
        console.print(f"{env_name}: paste your DeepSeek key. Input is hidden.", Console.DIM)
    api_key = normalize_api_key(getpass.getpass(f"Paste API key for {env_name}: "))
    if api_key:
        os.environ[env_name] = api_key
        console.print(f"API key received for {env_name} ({mask_api_key(api_key)}); it will be used for this run.", Console.GREEN)
    elif existing:
        console.print(f"Using existing {env_name} ({mask_api_key(existing)}).", Console.GREEN)
    else:
        raise ValueError(f"Missing {env_name}; choose no at Use LLM API to run dry-run mode.")


def choose_option(
    console: Console,
    title: str,
    options: list[tuple[str, str, str]],
    default: str,
    allow_custom: bool = True,
) -> str:
    console.print(title, Console.BOLD)
    console.print(
        "Suggestions. Type a number, press Enter for default"
        + (", or type a custom value." if allow_custom else "."),
        Console.DIM,
    )
    for index, (value, tag, description) in enumerate(options, start=1):
        tag_color = Console.GREEN if tag == "default" else Console.CYAN
        number = console.color(f"{index}.", Console.CYAN)
        label = console.color(value, Console.BOLD)
        marker = console.color(f"({tag})", tag_color)
        print(f"  {number} {label} {marker}")
        print(f"     {console.color(description, Console.DIM)}")
    raw = input(f"Choose {title.lower()} default: {default} ").strip()
    if not raw:
        return default
    if raw.isdigit():
        selected_index = int(raw) - 1
        if 0 <= selected_index < len(options):
            return options[selected_index][0]
    for value, _, _ in options:
        if raw.lower() == value.lower():
            return value
    if allow_custom:
        return raw
    console.print(f"Invalid choice, using default: {default}", Console.YELLOW)
    return default


def prompt_samples(console: Console, pipeline: VulSORPipeline, default: str) -> list[dict[str, Any]]:
    samples = pipeline.load_samples()
    console.print("Sample selection", Console.BOLD)
    console.print("Suggestions. Type a number, press Enter for default.", Console.DIM)
    options = [
        ("one", "suggestion", "Run exactly one dataset sample by sample_id or numeric id."),
        ("first-n", "default", "Run the first N samples after an optional offset."),
        ("all", "suggestion", "Run every sample in the selected dataset split."),
        ("random-n", "suggestion", "Run N randomly selected samples with an optional seed."),
        ("custom", "suggestion", "Use 3-50, 1,2,3, random:N, or explicit sample IDs."),
    ]
    for index, (value, tag, description) in enumerate(options, start=1):
        tag_color = Console.GREEN if tag == "default" else Console.CYAN
        print(f"  {console.color(f'{index}.', Console.CYAN)} {console.color(value, Console.BOLD)} {console.color(f'({tag})', tag_color)}")
        print(f"     {console.color(description, Console.DIM)}")
    mode_raw = input("Choose sample selection default: first-n ").strip()
    mode = "first-n"
    if mode_raw.isdigit() and 1 <= int(mode_raw) <= len(options):
        mode = options[int(mode_raw) - 1][0]
    elif mode_raw:
        mode = mode_raw

    if mode == "one":
        raw = input("Sample id default: 0 ").strip() or "0"
    elif mode == "first-n":
        limit = input("Limit [10]: ").strip() or "10"
        offset = input("Offset [0]: ").strip() or "0"
        start = int(offset)
        end = start + int(limit) - 1
        raw = f"{start}-{end}"
    elif mode == "all":
        raw = "all"
    elif mode == "random-n":
        count_raw = input("Random count default: 1 ").strip() or "1"
        seed_raw = input("Random seed optional: ").strip()
        return select_samples(samples, f"random:{count_raw}", pipeline.split, seed=seed_raw or None)
    elif mode == "custom":
        raw = input(f"Custom samples default: {default} ").strip() or default
    else:
        raw = mode

    if raw.lower() == "random":
        count_raw = input("Random count default: 1 ").strip() or "1"
        seed_raw = input("Random seed optional: ").strip()
        return select_samples(samples, f"random:{count_raw}", pipeline.split, seed=seed_raw or None)
    return select_samples(samples, raw, pipeline.split)


def select_samples(samples: list[dict[str, Any]], expression: str, split: str, seed: str | None = None) -> list[dict[str, Any]]:
    sample_by_id = {sample["sample_id"]: sample for sample in samples}
    expression = expression.strip()
    if not expression:
        raise ValueError("Sample selection is empty.")
    lowered = expression.lower()
    if lowered == "all":
        return samples
    if lowered.startswith("random"):
        count = 1
        if ":" in lowered:
            count = int(lowered.split(":", 1)[1])
        rng = random.Random(seed)
        return rng.sample(samples, k=min(count, len(samples)))

    selected_ids: list[str] = []
    for part in expression.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and all(piece.strip().isdigit() for piece in part.split("-", 1)):
            start_raw, end_raw = part.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            step = 1 if start <= end else -1
            selected_ids.extend(resolve_sample_token(str(number), samples, sample_by_id, split) for number in range(start, end + step, step))
        else:
            selected_ids.append(resolve_sample_token(part, samples, sample_by_id, split))

    missing = [sample_id for sample_id in selected_ids if sample_id not in sample_by_id]
    if missing:
        raise ValueError(f"Samples not found: {', '.join(missing)}")
    seen = set()
    selected = []
    for sample_id in selected_ids:
        if sample_id in seen:
            continue
        seen.add(sample_id)
        selected.append(sample_by_id[sample_id])
    return selected


def resolve_sample_token(token: str, samples: list[dict[str, Any]], sample_by_id: dict[str, dict[str, Any]], split: str) -> str:
    if token in sample_by_id:
        return token
    if token.isdigit():
        sample_id = f"{split}_{int(token):06d}"
        if sample_id in sample_by_id:
            return sample_id
        index = int(token)
        if 0 <= index < len(samples):
            return samples[index]["sample_id"]
        return sample_id
    return token


def inspect_samples(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]]) -> None:
    for index, sample in enumerate(samples):
        print_sample_separator(index)
        sample_id = sample["sample_id"]
        line_count = count_lines(sample.get("code", ""))
        ground_truth = pipeline.ground_truth_for_sample(sample_id) or {}
        console.print(f"{sample_id}: {line_count} source lines", Console.BOLD)
        print(f"  ground_truth: {format_ground_truth(ground_truth)}")
        print_status(console, pipeline, [sample])


def print_status(
    console: Console,
    pipeline: VulSORPipeline,
    samples: list[dict[str, Any]],
    summary: SummaryRecorder | None = None,
) -> None:
    for index, sample in enumerate(samples):
        print_sample_separator(index)
        sample_id = sample["sample_id"]
        statuses = pipeline.stage_status(sample_id)
        rendered = []
        for stage, state in statuses.items():
            if state == "ready":
                color = Console.GREEN
            elif state == "optional":
                color = Console.YELLOW
            else:
                color = Console.DIM
            rendered.append(console.color(f"S{stage}:{state}", color))
        print_output(f"  {sample_id}  " + "  ".join(rendered), summary)


class SummaryRecorder:
    def __init__(self, path: Path, project_root: Path) -> None:
        self.path = path
        self.project_root = project_root
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    @classmethod
    def create(
        cls,
        project_root: Path,
        *,
        split: str,
        stage: int,
        exact_stage: bool,
    ) -> "SummaryRecorder":
        mode = "only-stage" if exact_stage else RUN_PIPELINE_LABEL
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        suffix = f"{mode}-{stage}" if exact_stage else mode
        path = project_root / "stages" / "summary" / f"{timestamp}_{split}_{suffix}.txt"
        return cls(path, project_root)

    def write_line(self, text: str = "") -> None:
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")

    def display_path(self) -> str:
        return repo_relative_path(self.path, self.project_root)


def repo_relative_path(path: Path, project_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        return str(path)


def print_output(text: str = "", summary: SummaryRecorder | None = None) -> None:
    print(text)
    if summary is not None:
        summary.write_line(text)


def write_metrics_summary(
    console: Console,
    pipeline: VulSORPipeline,
    samples: list[dict[str, Any]],
    summary: SummaryRecorder | None = None,
) -> None:
    try:
        from scripts.eval_pipeline_metrics import evaluate_pipeline, write_summary_artifacts

        labels_path = pipeline.project_root / "data" / "PrimeVul_clean" / "labels" / f"{pipeline.split}.jsonl"
        context_path = pipeline.project_root / "data" / "build_context" / "context_clean" / f"{pipeline.split}.jsonl"
        sample_ids = {str(sample["sample_id"]) for sample in samples}
        result = evaluate_pipeline(
            labels_path,
            pipeline.stage_root,
            context_path=context_path,
            project_root=pipeline.project_root,
            sample_ids=sample_ids,
        )
        written, _ = write_summary_artifacts(
            pipeline.project_root / "stages" / "summary",
            pipeline.split,
            result,
            [],
            pipeline.project_root,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print_output(f"Metrics summary skipped: {exc}", summary)
        return

    markdown_paths = [path for path in written if path.suffix == ".md"]
    json_paths = [path for path in written if path.suffix == ".json"]
    if markdown_paths:
        print_output(f"Metrics markdown saved: {repo_relative_path(markdown_paths[0], pipeline.project_root)}", summary)
    if json_paths:
        print_output(f"Metrics JSON saved: {repo_relative_path(json_paths[0], pipeline.project_root)}", summary)


def print_sample_separator(index: int, summary: SummaryRecorder | None = None) -> None:
    if index > 0:
        print_output(summary=summary)


def run_samples_to_stage(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]], stage: int) -> None:
    total = len(samples)
    started = time.perf_counter()
    summary = SummaryRecorder.create(pipeline.project_root, split=pipeline.split, stage=stage, exact_stage=False)
    progress = PipelineProgressReporter(console, total, stage, started, exact_stage=False, summary=summary)
    try:
        for index, sample in enumerate(samples, start=1):
            print_sample_separator(index - 1, summary)
            progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{sample_run_label(stage, exact_stage=False)}]", Console.CYAN)
            record = pipeline.run_sample(
                sample,
                up_to_stage=stage,
                progress_callback=progress.for_sample(index, total),
            )
            progress.pause_live()
            try:
                print_stage_preview(console, pipeline, sample, stage, record, summary)
            finally:
                progress.resume_live()
    finally:
        progress.close()
    saved_text = f"Summary saved: {summary.display_path()}"
    console.print(saved_text, Console.DIM)
    summary.write_line(saved_text)
    write_metrics_summary(console, pipeline, samples, summary)


def run_samples_exact_stage(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]], stage: int) -> None:
    total = len(samples)
    started = time.perf_counter()
    summary = SummaryRecorder.create(pipeline.project_root, split=pipeline.split, stage=stage, exact_stage=True)
    progress = PipelineProgressReporter(console, total, stage, started, exact_stage=True, summary=summary)
    try:
        for index, sample in enumerate(samples, start=1):
            print_sample_separator(index - 1, summary)
            progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{sample_run_label(stage, exact_stage=True)}]", Console.CYAN)
            record = pipeline.run_exact_stage(
                sample,
                stage,
                progress_callback=progress.for_sample(index, total),
            )
            progress.pause_live()
            try:
                print_stage_preview(console, pipeline, sample, stage, record, summary)
            finally:
                progress.resume_live()
    finally:
        progress.close()
    saved_text = f"Summary saved: {summary.display_path()}"
    console.print(saved_text, Console.DIM)
    summary.write_line(saved_text)
    write_metrics_summary(console, pipeline, samples, summary)


class PipelineProgressReporter:
    def __init__(
        self,
        console: Console,
        sample_total: int,
        target_stage: int,
        started: float,
        exact_stage: bool,
        summary: SummaryRecorder | None = None,
    ) -> None:
        self.console = console
        self.sample_total = sample_total
        self.target_stage = target_stage
        self.started = started
        self.exact_stage = exact_stage
        self.summary = summary
        self.completed = 0
        self.current_sample_index = 0
        self.current_sample_total = sample_total
        self.current_sample_id = ""
        self.current_stage = 0
        self.current_detail = "starting"
        self.adjudication_units_estimate = 1
        self.current_adjudication_units = 0
        self.stage_started_at: dict[tuple[str, int], float] = {}
        self.child_started_at: dict[tuple[str, int, str, str], float] = {}
        self.attempt_started_at: dict[tuple[str, int, str, int], float] = {}
        self.last_plain_progress_at = 0.0
        self.tqdm_bar: Any = None
        self.rich_console: Any = None
        self.rich_progress: Any = None
        self.rich_task: Any = None
        if Tqdm is not None:
            self.tqdm_bar = Tqdm(
                total=self.sample_total,
                desc="Running pipeline",
                unit="sample",
                dynamic_ncols=True,
                leave=True,
            )
        elif self.console.enabled and Progress is not None and RichConsole is not None:
            self.rich_console = RichConsole()
            self.rich_progress = Progress(
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TaskProgressColumn(),
                TextColumn("samples {task.completed}/{task.total}"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                TextColumn("[dim]{task.fields[sample]}"),
                TextColumn("[dim]{task.fields[detail]}"),
                console=self.rich_console,
                transient=False,
            )
            self.rich_task = self.rich_progress.add_task(
                "Running pipeline",
                total=self.sample_total,
                sample="",
                detail="starting",
            )
            self.rich_progress.start()

    def for_sample(self, sample_index: int, sample_total: int):
        def report(event: dict[str, Any]) -> None:
            event["sample_index"] = sample_index
            event["sample_total"] = sample_total
            self(event)

        return report

    def __call__(self, event: dict[str, Any]) -> None:
        event_name = event.get("event")
        if event_name == "stage_start":
            self.print_stage_start(event)
        elif event_name == "stage_done":
            self.print_stage_done(event)
        elif event_name == "agent_start":
            self.print_child_start(event, "agent", event.get("agent_key", "unknown"))
        elif event_name == "agent_done":
            self.print_child_done(event, "agent", event.get("agent_key", "unknown"))
        elif event_name == "obligation_start":
            self.print_child_start(event, "obligation", event.get("obligation_id", "unknown"))
        elif event_name == "obligation_done":
            self.print_child_done(event, "obligation", event.get("obligation_id", "unknown"))
        elif event_name == "obligation_error":
            self.print_child_done(event, "obligation", event.get("obligation_id", "unknown"), failed=True)
        elif event_name == "llm_attempt_start":
            self.print_llm_attempt_start(event)
        elif event_name == "llm_attempt_done":
            self.print_llm_attempt_done(event)
        self.refresh_progress()

    def print_stage_start(self, event: dict[str, Any]) -> None:
        stage = int(event["stage"])
        sample_id = str(event.get("sample_id", ""))
        self.current_sample_index = int(event.get("sample_index", self.current_sample_index or 1))
        self.current_sample_total = int(event.get("sample_total", self.sample_total))
        self.current_sample_id = sample_id
        self.current_stage = stage
        self.current_detail = STAGE_LABELS[stage]
        if stage == 3:
            self.current_adjudication_units = 0
        self.stage_started_at[(sample_id, stage)] = time.perf_counter()
        stage_label = self.console.color(f"stage {stage}/{self.target_stage}", Console.PURPLE)
        self.log(f"  {stage_label}: {STAGE_LABELS[stage]} started", Console.DIM)

    def print_stage_done(self, event: dict[str, Any]) -> None:
        stage = int(event["stage"])
        sample_id = str(event.get("sample_id", ""))
        if stage == self.target_stage:
            self.completed += 1
            if self.tqdm_bar is not None:
                self.tqdm_bar.update(1)
        self.current_detail = f"{STAGE_LABELS[stage]} done"
        duration = time.perf_counter() - self.stage_started_at.get((sample_id, stage), time.perf_counter())
        self.log_stage_info(
            event,
            f"stage {stage}/{self.target_stage} done",
            Console.GREEN,
            duration=duration,
        )

    def print_child_start(self, event: dict[str, Any], label: str, name: str) -> None:
        index = int(event.get("index", 1))
        total = int(event.get("total", 1))
        sample_id = str(event.get("sample_id", ""))
        stage = int(event.get("stage", 0) or 0)
        self.child_started_at[(sample_id, stage, label, name)] = time.perf_counter()
        self.current_detail = f"{label} {index}/{total}: {name}"

    def print_child_done(self, event: dict[str, Any], label: str, name: str, failed: bool = False) -> None:
        index = int(event.get("index", 1))
        total = int(event.get("total", 1))
        stage = int(event.get("stage", 0) or 0)
        if label == "agent" and stage in {1, 2, 3}:
            if stage == 3:
                self.current_adjudication_units = 1
        elif label == "obligation":
            self.current_adjudication_units = max(self.current_adjudication_units, total)
            self.adjudication_units_estimate = max(self.adjudication_units_estimate, total)
        sample_id = str(event.get("sample_id", ""))
        started = self.child_started_at.get((sample_id, stage, label, name))
        duration = time.perf_counter() - started if started is not None else None
        status = "failed" if failed else "done"
        color = Console.RED if failed else Console.GREEN
        label_color = Console.YELLOW if label == "agent" else Console.BLUE
        label_text = self.console.color(f"{label} {index}/{total}", label_color)
        summary = event.get("summary")
        summary_text = f"  output: {summary}" if summary else ""
        self.log(
            f"    {label_text} {name}: {status}  "
            f"{format_token_usage(event.get('token_usage'))}"
            f"{format_token_limit(event.get('max_tokens'))}"
            f"{format_elapsed_suffix(duration)}"
            f"{summary_text}",
            color,
        )

    def print_llm_attempt_start(self, event: dict[str, Any]) -> None:
        attempt = int(event.get("attempt", 1))
        total = int(event.get("total", 1))
        agent_key = event.get("agent_key", "unknown")
        timeout = int(event.get("timeout_seconds", 0))
        max_tokens = int(event.get("max_tokens", 0) or 0)
        retry_notes = []
        if event.get("retry_without_reasoning"):
            retry_notes.append("reasoning off")
        token_multiplier = int(event.get("token_multiplier", 1) or 1)
        if token_multiplier > 1:
            retry_notes.append(f"max tokens x{token_multiplier}")
        retry_note = ", " + ", ".join(retry_notes) if retry_notes else ""
        sample_id = str(event.get("sample_id", ""))
        stage = int(event.get("stage", 0) or 0)
        self.attempt_started_at[(sample_id, stage, str(agent_key), attempt)] = time.perf_counter()
        self.current_detail = f"{agent_key} LLM attempt {attempt}/{total}"
        self.log(
            f"      LLM attempt {attempt}/{total}: {agent_key} started "
            f"(timeout {timeout}s, max={max_tokens}{retry_note})",
            Console.DIM,
        )

    def print_llm_attempt_done(self, event: dict[str, Any]) -> None:
        attempt = int(event.get("attempt", 1))
        total = int(event.get("total", 1))
        agent_key = event.get("agent_key", "unknown")
        errors = event.get("errors") or []
        failed = bool(errors)
        color = Console.YELLOW if failed else Console.GREEN
        status = "retry needed" if failed else "valid"
        sample_id = str(event.get("sample_id", ""))
        stage = int(event.get("stage", 0) or 0)
        started = self.attempt_started_at.get((sample_id, stage, str(agent_key), attempt))
        duration = time.perf_counter() - started if started is not None else None
        self.current_detail = f"{agent_key} LLM attempt {attempt}/{total} {status}"
        first_error = str(errors[0]) if errors else ""
        error_text = f"; {first_error}" if first_error else ""
        self.log(
            f"      LLM attempt {attempt}/{total}: {agent_key} {status} "
            f"{format_token_usage(event.get('token_usage'))}"
            f"{format_token_limit(event.get('max_tokens'))}"
            f"{format_elapsed_suffix(duration)}{error_text}",
            color,
        )

    def log_stage_info(
        self,
        event: dict[str, Any],
        message: str,
        color: str | None,
        duration: float | None = None,
    ) -> None:
        stage = int(event["stage"])
        summary = event.get("summary")
        status = event.get("status")
        parts = [
            f"  {color_stage_message(self.console, message)}",
            f"status={status}" if status else "",
            f"duration={format_duration(duration)}" if duration is not None else "",
            format_token_usage(event.get("token_usage")) if event.get("token_usage") is not None else "",
            f"info: {summary}" if summary else "",
        ]
        self.log("  ".join(part for part in parts if part), color)

    def running_label(self) -> str:
        if not self.current_stage:
            return "pipeline"
        label = STAGE_LABELS.get(self.current_stage, f"Stage {self.current_stage}")
        return label.replace("Stage ", "stage ", 1)

    def refresh_progress(self) -> None:
        elapsed = time.perf_counter() - self.started
        if self.tqdm_bar is not None:
            sample_text = f"sample {self.current_sample_index}/{self.current_sample_total}"
            if self.current_sample_id:
                sample_text += f" {self.current_sample_id}"
            self.tqdm_bar.set_postfix_str(
                f"{sample_text} | {self.current_detail} | elapsed {format_duration(elapsed)}",
                refresh=True,
            )
            return
        if self.rich_progress is not None and self.rich_task is not None:
            completed = min(self.completed, self.sample_total)
            sample_text = f"sample {self.current_sample_index}/{self.current_sample_total}"
            if self.current_sample_id:
                sample_text += f" {self.current_sample_id}"
            self.rich_progress.update(
                self.rich_task,
                total=self.sample_total,
                completed=completed,
                description=f"Running {self.running_label()}",
                sample=sample_text,
                detail=self.current_detail,
            )
            return
        return

    def print_plain_progress(self, elapsed: float) -> None:
        now = time.perf_counter()
        if now - self.last_plain_progress_at < 0.25:
            return
        self.last_plain_progress_at = now
        completed = min(self.completed, self.sample_total)
        width = max(10, min(30, terminal_width() - 80))
        bar = progress_bar(completed, self.sample_total, width)
        eta = estimate_eta(elapsed, completed, self.sample_total)
        eta_text = f" eta={format_duration(eta)}" if 0 < completed < self.sample_total else ""
        sample_text = f"sample={self.current_sample_index}/{self.current_sample_total}"
        if self.current_sample_id:
            sample_text += f" {self.current_sample_id}"
        self.console.print(
            f"  progress [{bar}] samples {completed}/{self.sample_total} elapsed={format_duration(elapsed)}{eta_text} "
            f"{sample_text} {self.current_detail}",
            Console.DIM,
        )

    def clear_live_line(self) -> None:
        return

    def pause_live(self) -> None:
        if self.tqdm_bar is not None:
            return
        if self.rich_progress is not None:
            self.rich_progress.stop()

    def resume_live(self) -> None:
        if self.tqdm_bar is not None:
            self.refresh_progress()
            return
        if self.rich_progress is not None:
            self.refresh_progress()
            self.rich_progress.start()

    def log(self, text: str, color: str | None = None) -> None:
        rendered = self.console.color(text, color) if color else text
        if self.tqdm_bar is not None:
            Tqdm.write(rendered)
            if self.summary is not None:
                self.summary.write_line(rendered)
            return
        if self.rich_progress is not None:
            self.rich_progress.console.print(rendered, markup=False)
            if self.summary is not None:
                self.summary.write_line(rendered)
            return
        self.console.print(text, color)
        if self.summary is not None:
            self.summary.write_line(rendered)

    def close(self) -> None:
        if self.tqdm_bar is not None:
            self.refresh_progress()
            self.tqdm_bar.close()
            return
        if self.rich_progress is not None:
            self.refresh_progress()
            self.rich_progress.stop()

    def total_units(self) -> int:
        return max(self.sample_total, self.completed, 1)

    def estimated_units_per_sample(self) -> int:
        stages = [self.target_stage] if self.exact_stage else range(1, self.target_stage + 1)
        total = 0
        for stage in stages:
            if stage == 1:
                total += 4
            elif stage in {2, 3}:
                total += 1
        return max(total, 1)


def print_stage_preview(
    console: Console,
    pipeline: VulSORPipeline,
    sample: dict[str, Any],
    stage: int,
    record: dict[str, Any] | None,
    summary: SummaryRecorder | None = None,
) -> None:
    sample_id = sample["sample_id"]
    output_path = pipeline._stage_file_for_number(sample_id, stage)
    print_output(f"  output: {repo_relative_path(output_path, pipeline.project_root)}", summary)
    if stage != 3 or not record:
        print_pipeline_token_usage(pipeline, sample, stage, current_record=record, summary=summary)
        print_status(console, pipeline, [sample], summary=summary)
        return

    output = record.get("output", {})
    prediction = output.get("label", "unknown")
    violation = output.get("violation")
    ground_truth = record.get("ground_truth") or output.get("ground_truth") or {}
    correct = output.get("correct")
    diagnostics = record.get("pipeline_diagnostics", {})
    warnings = len(diagnostics.get("warnings", []))
    missing = len(diagnostics.get("missing_information", []))
    conflicts = len(diagnostics.get("conflicts", []))
    errors = len(diagnostics.get("errors", []))
    quality_gate = record.get("quality_gate", {})

    evidence_status = output.get("evidence_status")
    if prediction == "AnalysisFailure":
        prediction_color = Console.YELLOW
    elif evidence_status == "insufficient":
        prediction_color = Console.YELLOW
    else:
        prediction_color = Console.RED if violation == 1 else Console.GREEN
    correctness_color = Console.GREEN if correct is True else Console.RED if correct is False else Console.YELLOW
    evidence_text = f"  evidence={evidence_status}" if evidence_status else ""
    print_output(
        f"  verdict: {quality_gate.get('status', 'unknown')}  "
        f"predict={console.color(str(prediction).lower(), prediction_color)}  "
        f"violation={violation}{evidence_text}",
        summary,
    )
    print_output(f"  ground_truth: {format_ground_truth(ground_truth)}", summary)
    print_output(f"  correct: {console.color(str(correct), correctness_color)}", summary)
    basis = output.get("decision_basis")
    triggering = output.get("triggering_obligations", [])
    if basis:
        print_output(f"  decision_basis: {basis}, triggering_obligations={triggering}", summary)
    if output.get("analysis_failure"):
        print_output(f"  analysis_failure_reasons: {output.get('analysis_failure_reasons', [])}", summary)
    violated_ids = output.get("violated_obligation_ids", [])
    if violated_ids:
        print_output(f"  violated_obligation_ids: {violated_ids}", summary)
    evaluation = output.get("evaluation_diagnostics", {})
    eval_text = ""
    if evaluation:
        eval_text = (
            f", diagnostic={evaluation.get('diagnostic_label', 'unknown')}"
            f", failure_stage={evaluation.get('failure_stage', 'unknown')}"
        )
    print_output(f"  diagnostics: obligations={quality_gate.get('adjudication_count', 0)}, warnings={warnings}, missing={missing}, conflicts={conflicts}, errors={errors}{eval_text}", summary)
    print_pipeline_token_usage(pipeline, sample, stage, current_record=record, summary=summary)


def print_pipeline_token_usage(
    pipeline: VulSORPipeline,
    sample: dict[str, Any],
    stage: int,
    current_record: dict[str, Any] | None = None,
    summary: SummaryRecorder | None = None,
) -> None:
    stage_usages = stage_token_usages(pipeline, sample["sample_id"], stage, current_record=current_record)
    if not stage_usages:
        return
    print_output("  tokens by stage:", summary)
    for stage_number, usage in stage_usages:
        print_output(f"    stage {stage_number}: {format_token_usage(usage, include_label=False)}", summary)
    total = sum_token_usages([usage for _, usage in stage_usages])
    print_output(f"  tokens total: {format_token_usage(total, include_label=False)}", summary)


def stage_token_usages(
    pipeline: VulSORPipeline,
    sample_id: str,
    stage: int,
    current_record: dict[str, Any] | None = None,
) -> list[tuple[int, dict[str, int]]]:
    usages = []
    for stage_number in range(1, stage + 1):
        record = current_record if stage_number == stage else None
        if record is None:
            path = pipeline._stage_file_for_number(sample_id, stage_number)
            if not path.exists():
                continue
            record = read_json_file(path)
        usages.append((stage_number, normalize_token_usage(record.get("token_usage"))))
    return usages


def normalize_token_usage(token_usage: Any) -> dict[str, int]:
    if not isinstance(token_usage, dict):
        token_usage = {}
    input_tokens = int(token_usage.get("input_tokens", 0) or 0)
    output_tokens = int(token_usage.get("output_tokens", 0) or 0)
    total_tokens = int(token_usage.get("total_tokens", 0) or 0)
    if total_tokens == 0:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def sum_token_usages(usages: list[dict[str, int]]) -> dict[str, int]:
    total = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    for usage in usages:
        total["input_tokens"] += usage["input_tokens"]
        total["output_tokens"] += usage["output_tokens"]
        total["total_tokens"] += usage["total_tokens"]
    return total


def format_token_usage(token_usage: Any, include_label: bool = True) -> str:
    if not isinstance(token_usage, dict):
        token_usage = {}
    input_tokens = int(token_usage.get("input_tokens", 0) or 0)
    output_tokens = int(token_usage.get("output_tokens", 0) or 0)
    total_tokens = int(token_usage.get("total_tokens", 0) or 0)
    if total_tokens == 0:
        total_tokens = input_tokens + output_tokens
    prefix = "tokens " if include_label else ""
    return f"{prefix}input={input_tokens}, output={output_tokens}, total={total_tokens}"


def format_token_limit(max_tokens: Any) -> str:
    if not max_tokens:
        return ""
    return f", max={int(max_tokens)}"


def color_stage_message(console: Console, message: str) -> str:
    if not message.startswith("stage "):
        return message
    head, sep, tail = message.partition(" done")
    if not sep:
        return message
    return f"{console.color(head, Console.PURPLE)}{sep}{tail}"


def format_ground_truth(ground_truth: dict[str, Any]) -> str:
    if not ground_truth:
        return "unknown"
    cwe = ground_truth.get("cwe") or []
    cwe_text = ",".join(cwe) if cwe else "none"
    return (
        f"{ground_truth.get('label', 'unknown')}, target={ground_truth.get('target')}, "
        f"cve={ground_truth.get('cve') or 'none'}, cwe={cwe_text}"
    )


def print_progress(console: Console, label: str, index: int, total: int, started: float) -> None:
    width = 28
    bar = progress_bar(index, total, width)
    elapsed = time.perf_counter() - started
    print(f"  {label} [{console.color(bar, Console.GREEN)}] {index}/{total} {elapsed:.2f}s")


def progress_bar(index: int, total: int, width: int) -> str:
    filled = int(width * min(max(index, 0), max(total, 1)) / max(total, 1))
    return "=" * filled + "-" * (width - filled)


def estimate_eta(elapsed: float, completed: int, total: int) -> float:
    if completed <= 0:
        return 0.0
    remaining = max(total - completed, 0)
    return elapsed * remaining / completed


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--:--"
    seconds = max(float(seconds), 0.0)
    total_seconds = int(seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def format_elapsed_suffix(seconds: float | None) -> str:
    return f"  elapsed={format_duration(seconds)}" if seconds is not None else ""


def pause() -> None:
    input("Press Enter to return to the menu...")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VulSOR prompt-agent pipeline.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--samples", default=None, help="Sample selection: all, random:N, 3-50, 1,2,3, or sample IDs.")
    parser.add_argument("--stage", type=int, choices=[1, 2, 3], default=3, help="Run pipeline up to this stage.")
    parser.add_argument("--only-stage", type=int, choices=[1, 2, 3], default=None, help="Run only this stage; previous outputs must exist.")
    parser.add_argument("--interactive", action="store_true", help="Open the guided CLI menu.")
    parser.add_argument("--dry-run", action="store_true", help="Render prompts without calling the configured LLM provider.")
    parser.add_argument("--use-llm", action="store_true", help="Call the configured LLM API. This is the default unless --dry-run is set.")
    parser.add_argument("--api-key", default=None, help="DeepSeek API key for this run. Prefer DEEPSEEK_API_KEY for shell history safety.")
    parser.add_argument("--overwrite", action="store_true", help="Clear this split's stage outputs before running.")
    parser.add_argument("--no-cache", action="store_true", help="Do not read or write the LLM response cache for this run.")
    parser.add_argument("--refresh-cache", action="store_true", help="Clear the LLM response cache before running, then save new responses.")
    parser.add_argument("--output-root", type=Path, default=None, help="Artifact directory; defaults to stages.")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    no_run_flags = len(sys.argv) == 1
    if args.interactive or no_run_flags:
        run_interactive(project_root)
        return

    if args.api_key:
        os.environ["DEEPSEEK_API_KEY"] = normalize_api_key(args.api_key)
    dry_run = args.dry_run and not args.use_llm
    if args.no_cache and args.refresh_cache:
        raise SystemExit("Choose either --no-cache or --refresh-cache, not both.")
    pipeline = VulSORPipeline(
        project_root=project_root,
        split=args.split,
        dry_run=dry_run,
        overwrite=args.overwrite,
        no_cache=args.no_cache,
        refresh_cache=args.refresh_cache,
        output_root=(args.output_root if args.output_root and args.output_root.is_absolute() else project_root / args.output_root) if args.output_root else None,
    )
    samples = pipeline.load_samples(limit=args.limit)
    if args.samples:
        samples = select_samples(samples, args.samples, args.split)

    try:
        console = Console()
        started = time.perf_counter()
        total = len(samples)
        summary = SummaryRecorder.create(
            project_root,
            split=args.split,
            stage=args.only_stage if args.only_stage is not None else args.stage,
            exact_stage=args.only_stage is not None,
        )
        progress = PipelineProgressReporter(
            console,
            total,
            args.only_stage if args.only_stage is not None else args.stage,
            started,
            exact_stage=args.only_stage is not None,
            summary=summary,
        )
        if args.only_stage is not None:
            try:
                for index, sample in enumerate(samples, start=1):
                    print_sample_separator(index - 1, summary)
                    progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{sample_run_label(args.only_stage, exact_stage=True)}]", Console.CYAN)
                    record = pipeline.run_exact_stage(
                        sample,
                        args.only_stage,
                        progress_callback=progress.for_sample(index, total),
                    )
                    progress.pause_live()
                    try:
                        print_stage_preview(console, pipeline, sample, args.only_stage, record, summary)
                    finally:
                        progress.resume_live()
            finally:
                progress.close()
        else:
            try:
                for index, sample in enumerate(samples, start=1):
                    print_sample_separator(index - 1, summary)
                    progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{sample_run_label(args.stage, exact_stage=False)}]", Console.CYAN)
                    record = pipeline.run_sample(
                        sample,
                        up_to_stage=args.stage,
                        progress_callback=progress.for_sample(index, total),
                    )
                    progress.pause_live()
                    try:
                        print_stage_preview(console, pipeline, sample, args.stage, record, summary)
                    finally:
                        progress.resume_live()
            finally:
                progress.close()
        saved_text = f"Summary saved: {summary.display_path()}"
        console.print(saved_text, Console.DIM)
        summary.write_line(saved_text)
        write_metrics_summary(console, pipeline, samples, summary)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Cannot run pipeline: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
