# Display / output formatter using colorama.

import sys
import io
import textwrap

# Force stdout to UTF-8 on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding='utf-8', errors='replace',
    )

from colorama import Fore, Back, Style, init as colorama_init

colorama_init(autoreset=True)




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
    + "    LOL-Exfiltrator v1.0  │  LOLBAS & GTFOBins Red Team Reference"
    + "\n    For authorised penetration testing and CTF use only.\n"
    + Fore.WHITE + Style.DIM
    + "    ─────────────────────────────────────────────────────────────\n"
    + Style.RESET_ALL
)




def print_banner() -> None:
    print(BANNER)


def print_section(title: str) -> None:
    width = 66
    border = f"{Fore.CYAN}{Style.BRIGHT}{'═' * width}{Style.RESET_ALL}"
    print(f"\n{border}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  {title}{Style.RESET_ALL}")
    print(border)


def print_result_header(index: int, name: str) -> None:
    print(
        f"\n  {Fore.YELLOW}{Style.BRIGHT}┌─ [{index}] {name}{Style.RESET_ALL}"
    )




def print_clear_command(command: str) -> None:
    print(f"\n  {Fore.GREEN}{Style.BRIGHT}  ◆ Clear Command:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}    {command}{Style.RESET_ALL}\n")


def print_obfuscated_command(command: str) -> None:
    print(f"  {Fore.RED}{Style.BRIGHT}  ◆ Obfuscated Command:{Style.RESET_ALL}")
    print(f"  {Fore.RED}{Style.BRIGHT}    {command}{Style.RESET_ALL}\n")


def print_technique(technique: str) -> None:
    print(
        f"  {Fore.MAGENTA}    Technique : "
        f"{Style.BRIGHT}{technique}{Style.RESET_ALL}"
    )


def print_stealth_note(note: str) -> None:
    _print_wrapped("  ◈ LOLBin Note", note, Fore.CYAN)


def print_obf_explanation(explanation: str) -> None:
    _print_wrapped("  ◈ Obf Rationale", explanation, Fore.YELLOW)


def print_requires(requires: str) -> None:
    _print_wrapped("  ◈ Requires", requires, Fore.BLUE)


def _print_wrapped(
    label: str,
    text: str,
    colour: str,
    width: int = 60,
) -> None:
    """Print a labelled block of text with soft word-wrapping."""
    prefix = f"    {colour}{Style.BRIGHT}{label}: {Style.RESET_ALL}"
    wrapped = textwrap.fill(
        text,
        width=width,
        subsequent_indent='                  ',
    )
    print(f"{prefix}{colour}{wrapped}{Style.RESET_ALL}")




def prompt(message: str, default: str = '') -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(
        f"  {Fore.GREEN}{Style.BRIGHT}▶ {message}{suffix}: "
        f"{Style.RESET_ALL}"
    ).strip()
    return raw if raw else default


def prompt_choice(message: str, choices: list) -> str:
    for i, choice in enumerate(choices, 1):
        print(f"    {Fore.CYAN}[{i}]{Style.RESET_ALL} {choice}")
    while True:
        raw = input(
            f"\n  {Fore.GREEN}{Style.BRIGHT}▶ {message} (number): "
            f"{Style.RESET_ALL}"
        ).strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        print(
            f"  {Fore.RED}  Invalid selection. "
            f"Enter a number between 1 and {len(choices)}.{Style.RESET_ALL}"
        )




def print_info(msg: str) -> None:
    print(f"  {Fore.BLUE}{Style.BRIGHT}[i]{Style.RESET_ALL} {msg}")


def print_warning(msg: str) -> None:
    print(
        f"  {Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} "
        f"{Fore.YELLOW}{msg}{Style.RESET_ALL}"
    )


def print_error(msg: str) -> None:
    print(
        f"  {Fore.RED}{Style.BRIGHT}[✗]{Style.RESET_ALL} "
        f"{Fore.RED}{msg}{Style.RESET_ALL}"
    )


def print_success(msg: str) -> None:
    print(
        f"  {Fore.GREEN}{Style.BRIGHT}[✓]{Style.RESET_ALL} "
        f"{Fore.GREEN}{msg}{Style.RESET_ALL}"
    )


def print_divider() -> None:
    print(f"  {Fore.WHITE}{Style.DIM}{'─' * 64}{Style.RESET_ALL}")
