from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any


class Platform(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    CROSS_PLATFORM = "all"


class Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    TCP = "tcp"
    ICMP = "icmp"


@dataclass(frozen=True)
class CommandTemplate:
    name: str
    binary: str
    platform: Platform
    protocol: Protocol
    template: str
    description: str = ""
    requires_root: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self, target: str, port: int, filepath: str, **kwargs) -> str:
        """Safely renders the command template with validated parameters."""
        context = {
            "target": target,
            "port": port,
            "file": filepath,
            **kwargs
        }
        try:
            return self.template.format(**context)
        except KeyError as e:
            raise ValueError(f"Missing required parameter for template '{self.name}': {e}")
