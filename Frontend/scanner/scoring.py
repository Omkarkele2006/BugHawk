from dataclasses import dataclass
from typing import List, Dict, Any
from .base import Finding

# Configurable deduction constraints
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 10.0,
    "MAJOR": 5.0,
    "MINOR": 1.0,
    "INFO": 0.5
}

# Configurable grade letter scopes (ordered descending)
GRADE_THRESHOLDS = [
    (90.0, "A+"),
    (80.0, "A"),
    (70.0, "B+"),
    (60.0, "B"),
    (50.0, "C"),
    (0.0, "F")
]

# Configurable threshold status limit
STATUS_THRESHOLD = 65.0

@dataclass
class HealthScore:
    overall_score: float
    grade: str
    status: str
    category_scores: Dict[str, float]       # "Security", "Code Quality", "Maintainability", "Dependencies"
    scoring_breakdown: List[Dict[str, Any]]  # Breakdown of individual deductions

class HealthScoreEngine:
    def _map_category(self, finding: Finding) -> str:
        """Determines which scoring category the finding belongs to."""
        if finding.scanner == "pip-audit":
            return "Dependencies"
        if finding.category == "security":
            return "Security"
        if finding.category in ["bugs", "performance"]:
            return "Code Quality"
        return "Maintainability"

    def calculate(self, findings: List[Finding]) -> HealthScore:
        """Calculates normalized overall and categorical scores based on findings."""
        deduction_breakdown = []
        category_deductions = {
            "Security": 0.0,
            "Code Quality": 0.0,
            "Maintainability": 0.0,
            "Dependencies": 0.0
        }
        total_deductions = 0.0

        for f in findings:
            sev = f.severity.upper()
            deduction = SEVERITY_DEDUCTIONS.get(sev, 0.5)
            cat = self._map_category(f)

            category_deductions[cat] += deduction
            total_deductions += deduction

            deduction_breakdown.append({
                "scanner": f.scanner,
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "severity": f.severity,
                "category": cat,
                "deduction": deduction
            })

        # Calculate category scores
        category_scores = {}
        for cat, ded in category_deductions.items():
            category_scores[cat] = max(0.0, 100.0 - ded)

        # Calculate overall score
        overall_score = max(0.0, 100.0 - total_deductions)

        # Map grade letter
        grade = "F"
        for threshold, letter in GRADE_THRESHOLDS:
            if overall_score >= threshold:
                grade = letter
                break

        # Map status
        status = "Good" if overall_score >= STATUS_THRESHOLD else "Needs Improvement"

        return HealthScore(
            overall_score=overall_score,
            grade=grade,
            status=status,
            category_scores=category_scores,
            scoring_breakdown=deduction_breakdown
        )
