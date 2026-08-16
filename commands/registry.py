"""Unified registry and search engine for all LOLBAS and GTFOBins techniques."""

from typing import List, Dict, Optional
from commands import TechniqueEntry
from commands.windows_lolbas import WINDOWS_COMMANDS
from commands.linux_gtfobins import LINUX_COMMANDS


class CommandRegistry:
    """
    Centralized registry providing indexing, searching, and filtering
    across all Windows LOLBAS and Linux GTFOBins techniques.
    """

    def __init__(self):
        self._windows_db: Dict[str, List[TechniqueEntry]] = WINDOWS_COMMANDS
        self._linux_db: Dict[str, List[TechniqueEntry]] = LINUX_COMMANDS

    def get_techniques(
        self,
        os_type: str,
        action: Optional[str] = None
    ) -> List[TechniqueEntry]:
        """Returns all techniques for a given OS and optional action filter."""
        os_type = os_type.lower()
        db = self._windows_db if os_type == "windows" else self._linux_db

        if action:
            return db.get(action.lower(), [])

        all_entries: List[TechniqueEntry] = []
        for action_entries in db.values():
            all_entries.extend(action_entries)
        return all_entries

    def filter_by_binary(
        self,
        os_type: str,
        binary_query: str,
        action: Optional[str] = None
    ) -> List[TechniqueEntry]:
        """Filters techniques matching a binary name or partial string."""
        entries = self.get_techniques(os_type, action)
        query = binary_query.lower().strip()
        return [e for e in entries if query in e.binary.lower()]

    def search(
        self,
        keyword: str,
        os_type: Optional[str] = None
    ) -> List[TechniqueEntry]:
        """Searches technique names, binaries, and stealth notes by keyword."""
        keyword = keyword.lower().strip()
        targets = [os_type] if os_type else ["windows", "linux"]
        results: List[TechniqueEntry] = []

        for os_t in targets:
            for entry in self.get_techniques(os_t):
                if (
                    keyword in entry.name.lower() or
                    keyword in entry.binary.lower() or
                    keyword in entry.stealth_note.lower()
                ):
                    results.append(entry)
        return results

    def get_stats(self) -> Dict[str, int]:
        """Returns statistics of all loaded techniques."""
        win_count = sum(len(v) for v in self._windows_db.values())
        lin_count = sum(len(v) for v in self._linux_db.values())
        return {
            "windows_techniques": win_count,
            "linux_techniques": lin_count,
            "total_techniques": win_count + lin_count,
        }


# Global registry singleton instance
registry = CommandRegistry()
