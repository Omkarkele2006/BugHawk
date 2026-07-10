from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict
import sys
import os

# Append parent dir to path to ensure scanner module can be imported if executing standalone
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from scanner.base import Finding

@dataclass
class Explanation:
    explanation: str
    why_it_matters: str
    possible_impact: str
    recommended_fix: str
    developer_friendly_summary: str

class FindingExplainer(ABC):
    @abstractmethod
    def explain_finding(self, finding: Finding) -> Explanation:
        """Analyzes a normalized Finding and generates a structured Explanation."""
        pass

    @abstractmethod
    def explain_findings(self, findings: List[Finding]) -> Dict[str, Explanation]:
        """Analyzes a list of findings and returns a mapping of finding rule_id (or title) to Explanation."""
        pass
