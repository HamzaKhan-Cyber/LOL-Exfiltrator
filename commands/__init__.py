"""Commands package — shared schema for technique entries."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TechniqueEntry:
    """
    Immutable schema for a single LOLBin / GTFOBin technique.
    Using a dataclass enforces that every entry has the required keys
    at construction time — a missing field raises TypeError immediately
    instead of a silent KeyError at runtime.
    """
    name: str
    binary: str
    template: str
    stealth_note: str
    requires: str = ""                       
    privilege: str = "user"                   
    detection_risk: str = "medium"            

    def __post_init__(self) -> None:
        required_placeholders = {"{ip}", "{port}", "{filename}"}
        present = {p for p in required_placeholders if p in self.template}
        if not present:
            raise ValueError(
                f"Template for '{self.name}' contains none of the required "
                f"placeholders ({required_placeholders}). At least one is expected."
            )

        if self.privilege not in ("user", "admin", "system"):
            raise ValueError(
                f"Invalid privilege '{self.privilege}' for '{self.name}'. "
                f"Must be 'user', 'admin', or 'system'."
            )

        if self.detection_risk not in ("low", "medium", "high"):
            raise ValueError(
                f"Invalid detection_risk '{self.detection_risk}' for '{self.name}'. "
                f"Must be 'low', 'medium', or 'high'."
            )