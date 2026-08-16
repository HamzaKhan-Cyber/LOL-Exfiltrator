import ipaddress
import re
from pathlib import Path
from typing import Union


class ValidationError(Exception):
    """Custom exception for CLI input validation failures."""
    pass


class InputValidator:
    # RFC 1123 compliant hostname regex
    HOSTNAME_REGEX = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )

    @staticmethod
    def validate_target(target: str) -> str:
        """Validates if the target is a valid IPv4, IPv6, or domain name."""
        target = target.strip()
        if not target:
            raise ValidationError("Target cannot be empty.")

        # Check IP address validity
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        # Check Hostname / Domain validity
        if target.lower() == "localhost" or InputValidator.HOSTNAME_REGEX.match(target):
            return target

        raise ValidationError(f"Invalid target format: '{target}'. Must be a valid IP or FQDN.")

    @staticmethod
    def validate_port(port: Union[int, str]) -> int:
        """Validates network port range (1 - 65535)."""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"Port must be an integer, got: '{port}'")

        if not (1 <= port_num <= 65535):
            raise ValidationError(f"Port out of range (1-65535): {port_num}")

        return port_num

    @staticmethod
    def sanitize_path(filepath: str) -> str:
        """Sanitizes local/remote file paths against illegal control characters."""
        filepath = filepath.strip()
        if not filepath:
            raise ValidationError("File path cannot be empty.")

        # Filter dangerous CLI injection characters
        forbidden_chars = [";", "&", "|", "`", "$", "\n", "\r"]
        if any(char in filepath for char in forbidden_chars):
            raise ValidationError(f"File path contains invalid/unsafe characters: '{filepath}'")

        return str(Path(filepath).as_posix())
