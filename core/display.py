
import sys
import io
import signal
import textwrap

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding='utf-8', errors='replace',
    )

from colorama import Fore, Back, Style, init as colorama_init

colorama_init(autoreset=True)

signal.signal(signal.SIGPIPE, signal.SIG_DFL) if hasattr(signal, 'SIGPIPE') else None



BANNER = (
    "\n"
    + Fore.RED + Style.BRIGHT
    + r"""
    ██╗      ██████╗ ██╗           ███████╗██╗  ██╗███████╗██╗██╗
    ██║     ██╔═══██╗██║           ██╔════╝╚██╗██╔╝██╔════╝██║██║
    ██║     ██║   ██║██║     █████╗█████╗   ╚███╔╝ █████╗  ██║██║
    ██║     ██║   ██║██║     ╚════╝██╔══╝   ██╔██╗ ██╔══╝  ██║██║
    ███████╗╚██████╔╝███████╗      ███████╗██╔╝ ██╗██║     ██║███████╗
    ╚══════╝ ╚═════╝ ╚══════╝      ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
"""
    + Fore.YELLOW + Style.NORMAL
    + "    LOL-Exfiltrator v1.1  │  LOLBAS & GTFOBins Red Team Reference"
    + "\n    For authorised penetration testing and CTF use only.\n"
    + Fore.WHITE + Style.DIM
    + "    ─────────────────────────────────────────────────────────────\n"
    + Style.RESET_ALL
)



def _safe_print(*args, **kwargs) -> None:
    """Print wrapper that silently handles BrokenPipeError."""
    try:
        print(*args, **kwargs)
    except BrokenPipeError:
        sys.exit(0)



def print_banner() -> None:
    _safe_print(BANNER)


def print_section(title: str) -> None:
    width = 66
    border = f"{Fore.CYAN}{Style.BRIGHT}{'═' * width}{Style.RESET_ALL}"
    _safe_print(f"\n{border}")
    _safe_print(f"{Fore.CYAN}{Style.BRIGHT}  {title}{Style.RESET_ALL}")
    _safe_print(border)


def print_result_header(index: int, name: str) -> None:
    _safe_print(
        f"\n  {Fore.YELLOW}{Style.BRIGHT}┌─ [{index}] {name}{Style.RESET_ALL}"
    )


def print_clear_command(command: str) -> None:
    _safe_print(f"\n  {Fore.GREEN}{Style.BRIGHT}  ◆ Clear Command:{Style.RESET_ALL}")
    _safe_print(f"  {Fore.WHITE}{Style.BRIGHT}    {command}{Style.RESET_ALL}\n")


def print_obfuscated_command(command: str) -> None:
    _safe_print(f"  {Fore.RED}{Style.BRIGHT}  ◆ Obfuscated Command:{Style.RESET_ALL}")
    _safe_print(f"  {Fore.RED}{Style.BRIGHT}    {command}{Style.RESET_ALL}\n")


def print_technique(technique: str) -> None:
    _safe_print(
        f"  {Fore.MAGENTA}    Technique : "
        f"{Style.BRIGHT}{technique}{Style.RESET_ALL}"
    )


def print_stealth_note(note: str) -> None:
    _print_wrapped("LOLBin Note", note, Fore.CYAN)


def print_obf_explanation(explanation: str) -> None:
    _print_wrapped("Obf Rationale", explanation, Fore.YELLOW)


def print_requires(requires: str) -> None:
    _print_wrapped("Requires", requires, Fore.BLUE)


def _print_wrapped(
    label: str,
    text: str,
    colour: str,
    width: int = 60,
) -> None:
    """Print a labelled block of text with soft word-wrapping.

    The continuation indent is calculated dynamically from the label
    length so that wrapped lines always align under the first word
    of the text body.
    """
    visible_prefix_len = 4 + 2 + len(label) + 2      
    indent = ' ' * visible_prefix_len

    wrapped = textwrap.fill(
        text,
        width=width,
        subsequent_indent=indent,
    )
    prefix = f"    {colour}{Style.BRIGHT}◈ {label}: {Style.RESET_ALL}"
    _safe_print(f"{prefix}{colour}{wrapped}{Style.RESET_ALL}")



def prompt(message: str, default: str = '') -> str:
    """Prompt user for free-text input. Ctrl-C / Ctrl-D exits cleanly."""
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(
            f"  {Fore.GREEN}{Style.BRIGHT}▶ {message}{suffix}: "
            f"{Style.RESET_ALL}"
        ).strip()
    except (KeyboardInterrupt, EOFError):
        _safe_print(f"\n  {Fore.YELLOW}[!] Cancelled.{Style.RESET_ALL}")
        sys.exit(0)
    return raw if raw else default


def prompt_choice(message: str, choices: list) -> str:
    """
    Display numbered choices and return the selected item.
    Supports 'q' / 'quit' to exit cleanly instead of an infinite loop.
    """
    for i, choice in enumerate(choices, 1):
        _safe_print(f"    {Fore.CYAN}[{i}]{Style.RESET_ALL} {choice}")
    _safe_print(f"    {Fore.WHITE}{Style.DIM}[q] Quit{Style.RESET_ALL}")

    while True:
        try:
            raw = input(
                f"\n  {Fore.GREEN}{Style.BRIGHT}▶ {message} (number or 'q'): "
                f"{Style.RESET_ALL}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            _safe_print(f"\n  {Fore.YELLOW}[!] Cancelled.{Style.RESET_ALL}")
            sys.exit(0)

        if raw.lower() in ('q', 'quit', 'exit'):
            _safe_print(f"  {Fore.YELLOW}[!] Exiting.{Style.RESET_ALL}")
            sys.exit(0)

        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]

        _safe_print(
            f"  {Fore.RED}  Invalid selection. "
            f"Enter 1–{len(choices)} or 'q' to quit.{Style.RESET_ALL}"
        )



def print_info(msg: str) -> None:
    _safe_print(f"  {Fore.BLUE}{Style.BRIGHT}[i]{Style.RESET_ALL} {msg}")


def print_warning(msg: str) -> None:
    _safe_print(
        f"  {Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} "
        f"{Fore.YELLOW}{msg}{Style.RESET_ALL}"
    )


def print_error(msg: str) -> None:
    _safe_print(
        f"  {Fore.RED}{Style.BRIGHT}[✗]{Style.RESET_ALL} "
        f"{Fore.RED}{msg}{Style.RESET_ALL}"
    )


def print_success(msg: str) -> None:
    _safe_print(
        f"  {Fore.GREEN}{Style.BRIGHT}[✓]{Style.RESET_ALL} "
        f"{Fore.GREEN}{msg}{Style.RESET_ALL}"
    )


def print_divider() -> None:
    _safe_print(f"  {Fore.WHITE}{Style.DIM}{'─' * 64}{Style.RESET_ALL}")


def print_privilege(privilege: str) -> None:
    """Display the required privilege level with color coding."""
    colors = {
        'user':   Fore.GREEN,
        'admin':  Fore.YELLOW,
        'system': Fore.RED,
    }
    icons = {
        'user':   '👤',
        'admin':  '🔑',
        'system': '⚙️',
    }
    color = colors.get(privilege, Fore.WHITE)
    icon  = icons.get(privilege, '❓')
    _safe_print(
        f"    {color}{Style.BRIGHT}◈ Privilege: "
        f"{Style.RESET_ALL}{color}{icon} {privilege.upper()}{Style.RESET_ALL}"
    )


def print_detection_risk(risk: str) -> None:
    """Display detection risk level with emoji indicator."""
    colors = {
        'low':    Fore.GREEN,
        'medium': Fore.YELLOW,
        'high':   Fore.RED,
    }
    icons = {
        'low':    '🟢',
        'medium': '🟡',
        'high':   '🔴',
    }
    color = colors.get(risk, Fore.WHITE)
    icon  = icons.get(risk, '⚪')
    _safe_print(
        f"    {color}{Style.BRIGHT}◈ Detection Risk: "
        f"{Style.RESET_ALL}{color}{icon} {risk.upper()}{Style.RESET_ALL}"
    )