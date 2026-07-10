from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    title: str          # e.g., "SQL Injection detected"
    description: str    # Detailed issue summary
    file_path: str      # Relative path to file from project root
    line_number: int    # Line number (1-indexed)
    severity: str       # "CRITICAL", "MAJOR", "MINOR", "INFO"
    category: str       # "security", "bugs", "performance", "codeSmells"

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, repo_path: str) -> List[Finding]:
        """Runs static analysis over the given repo directory path and returns a list of Findings."""
        pass
