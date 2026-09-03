"""Interactive terminal UI for VulSOR.

This module contains presentation and interactive input only.
It must not contain dataset, security-analysis, pipeline, or LLM logic.
"""

from __future__ import annotations

import sys
from enum import Enum

from rich.align import Align
from rich.console import Console
from rich.text import Text

console = Console()


class MenuAction(str, Enum):
    """Actions shown in the interactive VulSOR menu."""

    INSPECT = "inspect"
    DETECT = "detect"
    EVALUATE = "evaluate"
    RUN = "run"
    AGENT = "agent"
    DOCTOR = "doctor"
    VERSION = "version"
    EXIT = "exit"


_MENU_ITEMS: tuple[tuple[MenuAction, str], ...] = (
    (MenuAction.INSPECT, "Inspect a sample"),
    (MenuAction.DETECT, "Detect vulnerability"),
    (MenuAction.EVALUATE, "Evaluate dataset"),
    (MenuAction.RUN, "Run pipeline"),
    (MenuAction.AGENT, "Run semantic agents"),
    (MenuAction.DOCTOR, "Check environment"),
    (MenuAction.VERSION, "Show version"),
    (MenuAction.EXIT, "Exit"),
)


_VULSOR_LOGO = r"""
 ██████╗ ██████╗ ███████╗███╗   ██╗    ██╗   ██╗██╗   ██╗██╗      ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██║   ██║██║   ██║██║      ██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██║   ██║██║   ██║██║      ███████╗██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ╚██╗ ██╔╝██║   ██║██║      ╚════██║██║   ██║██╔══██╗
╚██████╔╝██║     ███████╗██║ ╚████║     ╚████╔╝ ╚██████╔╝███████╗ ███████║╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝      ╚═══╝   ╚═════╝ ╚══════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"""


def render_welcome() -> None:
    """Render the VulSOR welcome screen."""

    clear_screen()
    console.print()
    console.print(Align.center(Text(_VULSOR_LOGO, style="bold #C084FC")))
    console.print()
    console.print(
        Align.center(
            Text(
                "Semantic Vulnerability Research",
                style="dim",
            )
        )
    )
    console.print(
        Align.center(
            Text(
                "C / C++  •  Semantic Obligations  •  Verification",
                style="dim",
            )
        )
    )
    console.print()
    console.print()


def clear_screen() -> None:
    """Clear the terminal viewport and scrollback when possible."""

    if console.is_terminal:
        sys.stdout.write("\033[3J\033[2J\033[H")
        sys.stdout.flush()
    else:
        console.clear()


def render_main_menu(selected: int = 0) -> None:
    """Render the main interactive menu."""

    console.print("[bold]What would you like to do?[/bold]")
    console.print()

    for index, (_, label) in enumerate(_MENU_ITEMS):
        if index == selected:
            console.print(f"  [bold #C084FC]> {label}[/bold #C084FC]")
        else:
            console.print(f"    {label}")

    console.print()
    console.print("[dim]Up/Down Select    Enter Confirm    q Quit[/dim]")


def _read_key() -> str:
    """Read one key from the Windows terminal."""

    import msvcrt

    key = msvcrt.getwch()

    if key in ("\x00", "\xe0"):
        key = msvcrt.getwch()

        if key == "H":
            return "up"

        if key == "P":
            return "down"

        return "other"

    if key == "\r":
        return "enter"

    if key.lower() == "q":
        return "q"

    if key == "\x1b":
        return "escape"

    return "other"


def show_main_menu() -> MenuAction:
    """Show interactive menu and return selected action."""

    selected = 0

    while True:
        render_welcome()
        render_main_menu(selected)

        key = _read_key()

        if key == "up":
            selected = (selected - 1) % len(_MENU_ITEMS)

        elif key == "down":
            selected = (selected + 1) % len(_MENU_ITEMS)

        elif key == "enter":
            return _MENU_ITEMS[selected][0]

        elif key in {"q", "escape"}:
            return MenuAction.EXIT


def render_prompt() -> str:
    """Read one command from the interactive prompt."""

    return console.input("[bold cyan]vulsor>[/bold cyan] ").strip()


def print_error(message: str) -> None:
    """Render an interactive CLI error."""

    console.print(f"[bold red]Error:[/bold red] {message}")


def print_info(message: str) -> None:
    """Render an informational message."""

    console.print(f"[dim]{message}[/dim]")


def print_success(message: str) -> None:
    """Render a successful interactive message."""

    console.print(f"[bold green]OK[/bold green] {message}")
