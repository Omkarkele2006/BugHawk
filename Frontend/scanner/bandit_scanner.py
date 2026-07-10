import json
import subprocess
import os
import sys
import importlib.util
from typing import List
from .base import BaseScanner, Finding, map_severity

class BanditScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        
        # Check module availability
        if importlib.util.find_spec("bandit") is None:
            raise RuntimeError("Bandit package is not installed or available in the current Python environment.")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", repo_path, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                check=False
            )
            
            stdout = result.stdout.strip()
            if not stdout:
                return findings
                
            data = json.loads(stdout)
            for issue in data.get("results", []):
                full_path = issue.get("filename", "")
                rel_path = os.path.relpath(full_path, repo_path) if os.path.isabs(full_path) else full_path
                
                raw_severity = issue.get("issue_severity", "LOW")
                severity = map_severity(raw_severity)
                
                recommendation = (
                    "Avoid using insecure functions or importing vulnerable symbols. "
                    "Ensure user inputs are parameterized, validated, and escaped appropriately."
                )
                
                findings.append(Finding(
                    scanner="bandit",
                    category="security",
                    severity=severity,
                    file=rel_path,
                    line=int(issue.get("line_number", 1)),
                    rule_id=issue.get("test_id", "N/A"),
                    title=issue.get("issue_text", "Security Vulnerability"),
                    description=f"Vulnerability Details:\n{issue.get('code', '')}",
                    recommendation=recommendation,
                    confidence=issue.get("issue_confidence", "HIGH").upper()
                ))
        except Exception as e:
            # Raise the exception so ScanManager captures the exact failure details
            raise RuntimeError(f"Bandit execution encountered an error: {e}")
            
        return findings
