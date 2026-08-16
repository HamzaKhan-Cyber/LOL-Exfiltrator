import ipaddress
import re
from pathlib import Path
from typing import Union


class ValidationError(Exception):
    """Custom exception for CLI input validation failures."""
    pass


class InputValidator:
    """
    High-precision input validation and sanitization engine
    for network targets, ports, and file paths.
    """

    # RFC 1123 compliant hostname regex supporting subdomains & punycode
    HOSTNAME_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )

    # Windows reserved file names
    WIN_RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }

    # Dangerous CLI injection characters for filenames
    FORBIDDEN_FILE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f;`$&]')

    @classmethod
    def is_valid_target(cls, target: str) -> bool:
        """Returns True if the target is a valid IPv4, IPv6, localhost, or FQDN."""
        if not target or not isinstance(target, str):
            return False
        target = target.strip()
        if not target:
            return False

        # Check IPv4 / IPv6
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        # Check Localhost or valid FQDN domain
        if target.lower() in ("localhost", "127.0.0.1", "::1"):
            return True

        if cls.HOSTNAME_REGEX.match(target):
            return True

        # Support single-word local domain names (e.g. corp-dc, target-box)
        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}[a-zA-Z0-9]$", target):
            return True

        return False

    @classmethod
    def validate_target(cls, target: str) -> str:
        """Validates target and returns clean string, or raises ValidationError."""
        if not target:
            raise ValidationError("Target address cannot be empty.")
        target = target.strip()
        if not cls.is_valid_target(target):
            raise ValidationError(
                f"Invalid target format: '{target}'. Must be a valid IPv4, IPv6, or domain name."
            )
        return target

    @classmethod
    def validate_port(cls, port: Union[int, str]) -> int:
        """Validates network port range (1 - 65535)."""
        if port is None or str(port).strip() == "":
            raise ValidationError("Port cannot be empty.")
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"Port must be an integer, got: '{port}'")

        if not (1 <= port_num <= 65535):
            raise ValidationError(f"Port out of range (1-65535): {port_num}")

        return port_num

    @classmethod
    def is_valid_filename(cls, filename: str) -> bool:
        """Returns True if filename is clean and safe across platforms."""
        if not filename or not isinstance(filename, str):
            return False
        filename = filename.strip()
        if not filename or len(filename) > 255:
            return False

        # Check for forbidden control and shell injection characters
        if cls.FORBIDDEN_FILE_CHARS.search(filename):
            return False

        # Check Windows reserved base names
        base_stem = Path(filename).stem.upper()
        if base_stem in cls.WIN_RESERVED_NAMES:
            return False

        return True

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitizes filename and raises ValidationError if unsafe."""
        if not filename:
            raise ValidationError("Filename cannot be empty.")
        filename = filename.strip()
        if not cls.is_valid_filename(filename):
            raise ValidationError(
                f"Invalid filename: '{filename}'. Contains illegal characters or reserved system names."
            )
        return filename

    @classmethod
    def sanitize_path(cls, filepath: str) -> str:
        """Sanitizes local/remote file paths against illegal control characters."""
        if not filepath:
            raise ValidationError("File path cannot be empty.")
        filepath = filepath.strip()

        # Check for control characters
        forbidden_chars = [";", "&", "|", "`", "$", "\n", "\r", "\x00"]
        if any(char in filepath for char in forbidden_chars):
            raise ValidationError(f"File path contains invalid/unsafe control characters: '{filepath}'")

        return str(Path(filepath).as_posix())
