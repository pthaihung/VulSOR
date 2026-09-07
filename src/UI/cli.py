from __future__ import annotations

import argparse
import getpass
import os
import random
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

from src.agents.LLMClient import mask_api_key, normalize_api_key
from src.agents.Pipeline import STAGE_LABELS, VulSORPipeline, count_lines, read_json_file

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - optional terminal nicety
    tqdm = None


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
        yes_help_text="Call OpenRouter and run the real agent pipeline.",
        no_help_text="Render prompts locally without calling OpenRouter.",
    )
    dry_run = not use_llm
    if use_llm:
        prompt_api_key(console)
    overwrite = choose_bool(
        console,
        "Overwrite selected split outputs",
        default=False,
        yes_help_text="Clear previous stage outputs for this split first.",
        no_help_text="Keep existing stage outputs and reuse them when applicable.",
    )
    pipeline = VulSORPipeline(project_root=project_root, split=split, dry_run=dry_run, overwrite=overwrite)
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

            stage = choose_stage(console)
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


def choose_stage(console: Console) -> int:
    value = choose_option(
        console,
        title="Target stage",
        options=[
            ("1", "suggestion", "Build semantic model from source code."),
            ("2", "suggestion", "Build CPG evidence from Stage 1 output."),
            ("3", "suggestion", "Build obligations from Stage 1 and Stage 2."),
            ("4", "default", "Adjudicate obligations and produce final verdict."),
        ],
        default="4",
        allow_custom=False,
    )
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


def prompt_api_key(console: Console) -> None:
    env_name = "OPENROUTER_API_KEY"
    existing = normalize_api_key(os.environ.get(env_name, ""))
    if existing:
        os.environ[env_name] = existing
    console.print("LLM API key", Console.BOLD)
    if existing:
        console.print(f"{env_name}: existing key found ({mask_api_key(existing)}). Press Enter to keep it.", Console.DIM)
    else:
        console.print(f"{env_name}: paste your OpenRouter key. Input is hidden.", Console.DIM)
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
    for sample in samples:
        sample_id = sample["sample_id"]
        line_count = count_lines(sample.get("code", ""))
        ground_truth = pipeline.ground_truth_for_sample(sample_id) or {}
        console.print(f"{sample_id}: {line_count} source lines", Console.BOLD)
        print(f"  ground_truth: {format_ground_truth(ground_truth)}")
        print_status(console, pipeline, [sample])


def print_status(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]]) -> None:
    for sample in samples:
        sample_id = sample["sample_id"]
        statuses = pipeline.stage_status(sample_id)
        rendered = []
        for stage, state in statuses.items():
            color = Console.GREEN if state == "ready" else Console.DIM
            rendered.append(console.color(f"S{stage}:{state}", color))
        print(f"  {sample_id}  " + "  ".join(rendered))


def run_samples_to_stage(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]], stage: int) -> None:
    total = len(samples)
    started = time.perf_counter()
    progress = PipelineProgressReporter(console, total, stage, started, exact_stage=False)
    try:
        for index, sample in enumerate(samples, start=1):
            progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{STAGE_LABELS[stage]}]", Console.CYAN)
            record = pipeline.run_sample(
                sample,
                up_to_stage=stage,
                progress_callback=progress.for_sample(index, total),
            )
            progress.pause_live()
            try:
                print_stage_preview(console, pipeline, sample, stage, record)
            finally:
                progress.resume_live()
    finally:
        progress.close()


def run_samples_exact_stage(console: Console, pipeline: VulSORPipeline, samples: list[dict[str, Any]], stage: int) -> None:
    total = len(samples)
    started = time.perf_counter()
    progress = PipelineProgressReporter(console, total, stage, started, exact_stage=True)
    try:
        for index, sample in enumerate(samples, start=1):
            progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{STAGE_LABELS[stage]}]", Console.CYAN)
            record = pipeline.run_exact_stage(
                sample,
                stage,
                progress_callback=progress.for_sample(index, total),
            )
            progress.pause_live()
            try:
                print_stage_preview(console, pipeline, sample, stage, record)
            finally:
                progress.resume_live()
    finally:
        progress.close()


class PipelineProgressReporter:
    def __init__(
        self,
        console: Console,
        sample_total: int,
        target_stage: int,
        started: float,
        exact_stage: bool,
    ) -> None:
        self.console = console
        self.sample_total = sample_total
        self.target_stage = target_stage
        self.started = started
        self.exact_stage = exact_stage
        self.completed = 0
        self.current_sample_index = 0
        self.current_sample_total = sample_total
        self.current_sample_id = ""
        self.current_stage = 0
        self.current_detail = "starting"
        self.stage4_units_estimate = 1
        self.current_stage4_obligations = 0
        self.stage_started_at: dict[tuple[str, int], float] = {}
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.live_paused = False
        self.spinner_index = 0
        self.last_live_width = 0
        self.tqdm_bar: Any = None
        self.thread: threading.Thread | None = None
        if self.console.enabled and tqdm is not None:
            self.tqdm_bar = tqdm(
                total=self.total_units(),
                desc="Running pipeline",
                unit="step",
                dynamic_ncols=True,
                leave=True,
                bar_format="{desc} {bar} {n_fmt}/{total_fmt} {elapsed}",
            )
        elif self.console.enabled:
            self.thread = threading.Thread(target=self.render_loop, daemon=True)
            self.thread.start()

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
        with self.lock:
            self.current_sample_index = int(event.get("sample_index", self.current_sample_index or 1))
            self.current_sample_total = int(event.get("sample_total", self.sample_total))
            self.current_sample_id = sample_id
            self.current_stage = stage
            self.current_detail = STAGE_LABELS[stage]
            if stage == 4:
                self.current_stage4_obligations = 0
            self.stage_started_at[(sample_id, stage)] = time.perf_counter()
        stage_label = self.console.color(f"stage {stage}/{self.target_stage}", Console.PURPLE)
        self.log(f"  {stage_label}: {STAGE_LABELS[stage]} started", Console.DIM)

    def print_stage_done(self, event: dict[str, Any]) -> None:
        stage = int(event["stage"])
        sample_id = str(event.get("sample_id", ""))
        with self.lock:
            if stage == 2 or (stage == 4 and self.current_stage4_obligations == 0):
                self.completed += 1
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
        with self.lock:
            self.current_detail = f"{label} {index}/{total}: {name}"

    def print_child_done(self, event: dict[str, Any], label: str, name: str, failed: bool = False) -> None:
        index = int(event.get("index", 1))
        total = int(event.get("total", 1))
        stage = int(event.get("stage", 0) or 0)
        with self.lock:
            if label == "agent" and stage in {1, 3}:
                self.completed += 1
            elif label == "obligation":
                self.current_stage4_obligations = max(self.current_stage4_obligations, total)
                self.stage4_units_estimate = max(self.stage4_units_estimate, total)
                self.completed += 1
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
        with self.lock:
            self.current_detail = f"{agent_key} LLM attempt {attempt}/{total}"
        if attempt > 1 or retry_note:
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
        with self.lock:
            self.current_detail = f"{agent_key} LLM attempt {attempt}/{total} {status}"
        if failed:
            first_error = str(errors[0]) if errors else "validation failed"
            self.log(
                f"      LLM attempt {attempt}/{total}: {agent_key} retry needed "
                f"{format_token_usage(event.get('token_usage'))}"
                f"{format_token_limit(event.get('max_tokens'))}; {first_error}",
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

    def render_loop(self) -> None:
        while not self.stop_event.wait(0.25):
            with self.lock:
                if self.live_paused:
                    continue
            self.render_live_line()

    def render_live_line(self) -> None:
        with self.lock:
            line = self.live_line()
            self.spinner_index += 1
            self.write_live_line_locked(line)

    def live_line(self) -> str:
        total_units = self.total_units()
        completed = min(self.completed, total_units)
        elapsed = time.perf_counter() - self.started
        bar = progress_bar(completed, total_units, width=36)
        label = self.running_label()
        sample_text = f"sample {self.current_sample_index}/{self.current_sample_total}"
        if self.current_sample_id:
            sample_text += f" {self.current_sample_id}"
        return (
            f"Running {label} [{bar}] {completed}/{total_units} "
            f"{format_duration(elapsed)}  {sample_text}  {self.current_detail}"
        )

    def running_label(self) -> str:
        if not self.current_stage:
            return "pipeline"
        label = STAGE_LABELS.get(self.current_stage, f"Stage {self.current_stage}")
        return label.replace("Stage ", "stage ", 1)

    def refresh_progress(self) -> None:
        if self.tqdm_bar is None:
            return
        with self.lock:
            total_units = self.total_units()
            if self.tqdm_bar.total != total_units:
                self.tqdm_bar.total = total_units
            self.tqdm_bar.n = min(self.completed, total_units)
            self.tqdm_bar.set_description_str(f"Running {self.running_label()}")
            self.tqdm_bar.refresh()

    def write_live_line_locked(self, line: str) -> None:
        width = max(terminal_width() - 1, 40)
        rendered = line[:width].ljust(max(self.last_live_width, len(line[:width])))
        sys.stdout.write("\r" + self.console.color(rendered, Console.CYAN))
        sys.stdout.flush()
        self.last_live_width = len(rendered)

    def clear_live_line(self) -> None:
        if self.tqdm_bar is not None:
            self.tqdm_bar.clear()
            return
        if not self.console.enabled:
            return
        with self.lock:
            self.clear_live_line_locked()

    def pause_live(self) -> None:
        if self.tqdm_bar is not None:
            self.tqdm_bar.clear()
            return
        if not self.console.enabled:
            return
        with self.lock:
            self.live_paused = True
            self.clear_live_line_locked()

    def resume_live(self) -> None:
        if self.tqdm_bar is not None:
            self.tqdm_bar.refresh()
            return
        if not self.console.enabled:
            return
        with self.lock:
            self.live_paused = False
            if not self.stop_event.is_set():
                self.write_live_line_locked(self.live_line())

    def clear_live_line_locked(self) -> None:
        if self.last_live_width:
            sys.stdout.write("\r" + " " * self.last_live_width + "\r")
            sys.stdout.flush()
            self.last_live_width = 0

    def log(self, text: str, color: str | None = None) -> None:
        with self.lock:
            if self.tqdm_bar is not None:
                self.tqdm_bar.write(self.console.color(text, color) if color else text)
                return
            if self.console.enabled:
                self.clear_live_line_locked()
            self.console.print(text, color)
            if self.console.enabled and not self.stop_event.is_set():
                self.write_live_line_locked(self.live_line())

    def close(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1.0)
        if self.tqdm_bar is not None:
            self.refresh_progress()
            self.tqdm_bar.close()
        else:
            self.clear_live_line()

    def total_units(self) -> int:
        return max(self.sample_total * self.estimated_units_per_sample(), self.completed, 1)

    def estimated_units_per_sample(self) -> int:
        stages = [self.target_stage] if self.exact_stage else range(1, self.target_stage + 1)
        total = 0
        for stage in stages:
            if stage == 1:
                total += 4
            elif stage in {2, 3}:
                total += 1
            elif stage == 4:
                total += max(self.stage4_units_estimate, 1)
        return max(total, 1)


def print_stage_preview(console: Console, pipeline: VulSORPipeline, sample: dict[str, Any], stage: int, record: dict[str, Any] | None) -> None:
    sample_id = sample["sample_id"]
    output_path = pipeline._stage_file_for_number(sample_id, stage)
    print(f"  output: {output_path}")
    if stage != 4 or not record:
        print_pipeline_token_usage(pipeline, sample, stage, current_record=record)
        print_status(console, pipeline, [sample])
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

    prediction_color = Console.RED if violation == 1 else Console.GREEN
    correctness_color = Console.GREEN if correct is True else Console.RED if correct is False else Console.YELLOW
    print(f"  verdict: {quality_gate.get('status', 'unknown')}  predict={console.color(str(prediction).lower(), prediction_color)}  violation={violation}")
    print(f"  ground_truth: {format_ground_truth(ground_truth)}")
    print(f"  correct: {console.color(str(correct), correctness_color)}")
    violated_ids = output.get("violated_obligation_ids", [])
    if violated_ids:
        print(f"  violated_obligation_ids: {violated_ids}")
    print(f"  diagnostics: obligations={quality_gate.get('adjudication_count', 0)}, warnings={warnings}, missing={missing}, conflicts={conflicts}, errors={errors}")
    print_pipeline_token_usage(pipeline, sample, stage, current_record=record)


def print_pipeline_token_usage(
    pipeline: VulSORPipeline,
    sample: dict[str, Any],
    stage: int,
    current_record: dict[str, Any] | None = None,
) -> None:
    stage_usages = stage_token_usages(pipeline, sample["sample_id"], stage, current_record=current_record)
    if not stage_usages:
        return
    print("  tokens by stage:")
    for stage_number, usage in stage_usages:
        print(f"    stage {stage_number}: {format_token_usage(usage, include_label=False)}")
    total = sum_token_usages([usage for _, usage in stage_usages])
    print(f"  tokens total: {format_token_usage(total, include_label=False)}")


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


def pause() -> None:
    input("Press Enter to return to the menu...")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VulSOR prompt-agent pipeline.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--samples", default=None, help="Sample selection: all, random:N, 3-50, 1,2,3, or sample IDs.")
    parser.add_argument("--stage", type=int, choices=[1, 2, 3, 4], default=4, help="Run pipeline up to this stage.")
    parser.add_argument("--only-stage", type=int, choices=[1, 2, 3, 4], default=None, help="Run only this stage; previous outputs must exist.")
    parser.add_argument("--interactive", action="store_true", help="Open the guided CLI menu.")
    parser.add_argument("--dry-run", action="store_true", help="Render prompts without calling OpenRouter.")
    parser.add_argument("--use-llm", action="store_true", help="Call the configured LLM API. This is the default unless --dry-run is set.")
    parser.add_argument("--api-key", default=None, help="OpenRouter API key for this run. Prefer OPENROUTER_API_KEY for shell history safety.")
    parser.add_argument("--overwrite", action="store_true", help="Clear this split's stage outputs before running.")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    no_run_flags = len(sys.argv) == 1
    if args.interactive or no_run_flags:
        run_interactive(project_root)
        return

    if args.api_key:
        os.environ["OPENROUTER_API_KEY"] = normalize_api_key(args.api_key)
    dry_run = args.dry_run and not args.use_llm
    pipeline = VulSORPipeline(
        project_root=project_root,
        split=args.split,
        dry_run=dry_run,
        overwrite=args.overwrite,
    )
    samples = pipeline.load_samples(limit=args.limit)
    if args.samples:
        samples = select_samples(samples, args.samples, args.split)

    try:
        console = Console()
        started = time.perf_counter()
        total = len(samples)
        progress = PipelineProgressReporter(
            console,
            total,
            args.only_stage if args.only_stage is not None else args.stage,
            started,
            exact_stage=args.only_stage is not None,
        )
        if args.only_stage is not None:
            try:
                for index, sample in enumerate(samples, start=1):
                    progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{STAGE_LABELS[args.only_stage]}]", Console.CYAN)
                    record = pipeline.run_exact_stage(
                        sample,
                        args.only_stage,
                        progress_callback=progress.for_sample(index, total),
                    )
                    progress.pause_live()
                    try:
                        print_stage_preview(console, pipeline, sample, args.only_stage, record)
                    finally:
                        progress.resume_live()
            finally:
                progress.close()
        else:
            try:
                for index, sample in enumerate(samples, start=1):
                    progress.log(f"Sample {index}/{total}: {sample['sample_id']} [{STAGE_LABELS[args.stage]}]", Console.CYAN)
                    record = pipeline.run_sample(
                        sample,
                        up_to_stage=args.stage,
                        progress_callback=progress.for_sample(index, total),
                    )
                    progress.pause_live()
                    try:
                        print_stage_preview(console, pipeline, sample, args.stage, record)
                    finally:
                        progress.resume_live()
            finally:
                progress.close()
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Cannot run pipeline: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
