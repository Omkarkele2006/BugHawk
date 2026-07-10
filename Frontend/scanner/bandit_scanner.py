import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding

class BanditScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("bandit"):
            # Bandit is not installed locally; skip scan gracefully
            print("[BanditScanner] 'bandit' executable not found in PATH. Skipping.")
            return findings

        try:
            # Run bandit recursively over target path, output to JSON
            result = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                check=False
            )
            
            # Bandit exits with 1 if issues are found, which is fine since check=False
            if not result.stdout.strip():
                return findings
                
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                full_path = issue.get("filename", "")
                rel_path = os.path.relpath(full_path, repo_path) if os.path.isabs(full_path) else full_path
                
                # Normalize severity
                bandit_sev = issue.get("issue_severity", "LOW").upper()
                severity = "CRITICAL" if bandit_sev == "HIGH" else ("MAJOR" if bandit_sev == "MEDIUM" else "MINOR")
                
                findings.append(Finding(
                    title=issue.get("issue_text", "Security Issue"),
                    description=(
                        f"ID: {issue.get('test_id', 'N/A')}\n"
                        f"Ref: {issue.get('test_link', 'N/A')}\n"
                        f"Code:\n{issue.get('code', '')}"
                    ),
                    file_path=rel_path,
                    line_number=int(issue.get("line_number", 1)),
                    severity=severity,
                    category="security"
                ))
        except Exception as e:
            print(f"[BanditScanner] Scan encountered an error: {e}")
            
        return findings
