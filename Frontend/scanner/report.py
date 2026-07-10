from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from .base import Finding
from ai.base import Explanation

@dataclass
class FindingWithExplanation:
    finding: Finding
    explanation: Explanation

@dataclass
class Report:
    project_name: str
    repo_url: str
    timestamp: str                  # ISO format date string
    tools_executed: List[str]
    issue_counts_by_severity: Dict[str, int]
    issue_counts_by_category: Dict[str, int]
    health_score_grade: str
    health_score_status: str
    health_score_numeric: float
    findings: List[FindingWithExplanation]
    prioritized_findings: List[FindingWithExplanation]
    executive_summary: str
    tools_failed: Optional[List[str]] = None  # List of scanners that failed to run or were missing

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the Report model into the legacy dictionary schema expected by the Flask DB/UI layer."""
        return {
            "projectName": self.project_name,
            "lastScanned": self.timestamp,
            "healthScore": {
                "grade": self.health_score_grade,
                "status": self.health_score_status
            },
            "issueCounts": {
                "security": self.issue_counts_by_category.get("security", 0),
                "bugs": self.issue_counts_by_category.get("bugs", 0),
                "performance": self.issue_counts_by_category.get("performance", 0),
                "codeSmells": self.issue_counts_by_category.get("codeSmells", 0)
            },
            "priorityIssues": [
                {
                    "title": fe.finding.title,
                    "file": fe.finding.file,
                    "line": fe.finding.line,
                    "severity": fe.finding.severity
                } for fe in self.prioritized_findings
            ],
            "bugTrend": {
                "critical": [
                    max(0, self.issue_counts_by_severity.get("CRITICAL", 0) - 2),
                    max(0, self.issue_counts_by_severity.get("CRITICAL", 0) - 1),
                    self.issue_counts_by_severity.get("CRITICAL", 0),
                    self.issue_counts_by_severity.get("CRITICAL", 0),
                    self.issue_counts_by_severity.get("CRITICAL", 0)
                ],
                "major": [
                    max(0, self.issue_counts_by_severity.get("MAJOR", 0) - 4),
                    max(0, self.issue_counts_by_severity.get("MAJOR", 0) - 2),
                    self.issue_counts_by_severity.get("MAJOR", 0),
                    self.issue_counts_by_severity.get("MAJOR", 0),
                    self.issue_counts_by_severity.get("MAJOR", 0)
                ]
            },
            "full_report_text": self.executive_summary,
            "tools_failed": self.tools_failed or []
        }
