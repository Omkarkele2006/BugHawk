import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding, map_severity

class BanditScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("bandit"):
            print("[BanditScanner] 'bandit' executable not found in PATH. Skipping.")
            return findings

        try:
            result = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if not result.stdout.strip():
                return findings
                
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                full_path = issue.get("filename", "")
                rel_path = os.path.relpath(full_path, repo_path) if os.path.isabs(full_path) else full_path
                
                raw_severity = issue.get("issue_severity", "LOW")
                severity = map_severity(raw_severity)
                
                # Propose a standard security recommendation
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
            print(f"[BanditScanner] Scan encountered an error: {e}")
            
        return findings
