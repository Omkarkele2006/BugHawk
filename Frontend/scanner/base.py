from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    scanner: str        # e.g., "ruff", "bandit", "radon", "pip-audit"
    category: str       # "security", "bugs", "performance", "codeSmells"
    severity: str       # Normalized: "CRITICAL", "MAJOR", "MINOR", "INFO"
    file: str           # Relative file path
    line: int           # Line number (1-indexed)
    rule_id: str        # Rule code or identifier (e.g. "B101", "F401")
    title: str          # Concise title summary
    description: str    # Detailed diagnostic message
    recommendation: str # Actionable fix recommendation
    confidence: str = "HIGH"  # Confidence score ("HIGH", "MEDIUM", "LOW")

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, repo_path: str) -> List[Finding]:
        """Runs static analysis over the given repo directory path and returns a list of Findings."""
        pass

def map_severity(raw_severity: str) -> str:
    """Centralized mapper to normalize severity strings from various tools into standard scopes.
    
    Standard outputs: "CRITICAL", "MAJOR", "MINOR", "INFO"
    """
    if not raw_severity:
        return "INFO"
        
    raw = str(raw_severity).strip().upper()
    
    # Critical and High mappings
    if raw in ["CRITICAL", "HIGH", "E", "F", "ERROR", "FATAL"]:
        return "CRITICAL"
        
    # Major and Medium mappings
    if raw in ["MAJOR", "MEDIUM", "WARNING", "C", "D", "WARN"]:
        return "MAJOR"
        
    # Minor and Low mappings
    if raw in ["MINOR", "LOW", "A", "B", "STYLE", "CONVENTIONAL"]:
        return "MINOR"
        
    # Information/Default
    return "INFO"
