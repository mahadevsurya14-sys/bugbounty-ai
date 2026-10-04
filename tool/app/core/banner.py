"""
MAHADU Branding & Banner Module for BugBounty-AI.
Centralizes all visual identity, ASCII art, status display, and about/version output.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__version__ = "0.1.0"
__author__ = "Mahadev Suryavanshi"
__brand__ = "MAHADU"
__project__ = "BugBounty-AI"
__tagline__ = "AI-Assisted Bug Bounty Recon & Security Research Platform"
__license__ = "Apache-2.0"

BANNER_ART = r"""
███╗   ███╗ █████╗ ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗
████╗ ████║██╔══██╗██║  ██║██╔══██╗██╔══██╗██║   ██║
██╔████╔██║███████║███████║███████║██║  ██║██║   ██║
██║╚██╔╝██║██╔══██║██╔══██║██╔══██║██║  ██║██║   ██║
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║██████╔╝╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝
"""

console = Console()


def show_banner():
    """Display the branded MAHADU startup banner."""
    banner_text = Text(BANNER_ART, style="bold cyan")
    console.print(banner_text, highlight=False)

    subtitle = Text()
    subtitle.append("MAHADU", style="bold white")
    subtitle.append(" Security Research\n", style="dim white")
    subtitle.append(f"{__project__}\n", style="bold cyan")
    subtitle.append(__tagline__, style="dim")
    console.print(subtitle, justify="center")
    console.print()


def show_status():
    """Display system readiness indicators."""
    console.print(
        Panel(
            "[bold white][ MAHADU SECURITY RESEARCH ][/bold white]",
            style="cyan",
            expand=False,
        ),
        justify="center",
    )
    console.print()

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=None,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Module", style="white", min_width=18)
    table.add_column("Status", style="bold green", min_width=8)

    modules = [
        ("Scope Engine", "READY"),
        ("Recon Engine", "READY"),
        ("OWASP Engine", "READY"),
        ("AI Engine", "READY"),
        ("Evidence Engine", "READY"),
        ("Report Engine", "READY"),
    ]

    for name, status in modules:
        table.add_row(f"  {name}", f"[bold green]✓[/bold green] {status}")

    console.print(table, justify="center")
    console.print()
    console.print(
        "[dim]Mode:[/dim] [bold yellow]AUTHORIZED SECURITY RESEARCH ONLY[/bold yellow]",
        justify="center",
    )
    console.print()


def show_footer():
    """Display branded version footer."""
    footer = Text()
    footer.append(f"{__project__} v{__version__}", style="dim")
    footer.append("  •  ", style="dim")
    footer.append(f"Created by {__brand__}", style="dim cyan")
    footer.append("  •  ", style="dim")
    footer.append("Security Research • Recon • Web Application Security", style="dim")
    console.print(footer, justify="center")
    console.print()


def show_about():
    """Display the full about screen."""
    console.print(
        Panel(
            "[bold cyan]MAHADU[/bold cyan]\n"
            "[bold white]BugBounty-AI Security Tool[/bold white]",
            style="cyan",
            expand=False,
            padding=(1, 8),
        ),
        justify="center",
    )
    console.print()

    info_lines = [
        ("Project", __project__),
        ("Author", __author__),
        ("Brand", __brand__),
        ("Purpose", "Authorized security research and bug bounty workflow automation"),
        ("Version", __version__),
        ("License", __license__),
    ]

    table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    table.add_column("Key", style="bold white", min_width=12)
    table.add_column("Value", style="cyan")

    for key, val in info_lines:
        table.add_row(f"  {key}:", val)

    console.print(table)
    console.print()
    console.print(
        "[dim]For authorized security research, owned systems, labs, "
        "and explicitly in-scope bug bounty programs only.[/dim]",
        justify="center",
    )
    console.print()


def show_version():
    """Display version string."""
    console.print(f"[bold cyan]MAHADU[/bold cyan] [bold white]{__project__}[/bold white]")
    console.print(f"[dim]Version:[/dim] {__version__}")


def show_welcome():
    """Full branded welcome screen shown when CLI is invoked without a command."""
    show_banner()
    show_status()
    show_footer()


def branded_header(section: str) -> str:
    """Return a short branded section header like 'MAHADU // Recon'."""
    return f"MAHADU // {section}"
