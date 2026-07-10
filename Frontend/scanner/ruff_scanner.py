import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding

class RuffScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("ruff"):
            # Ruff is not installed locally; skip scan gracefully
            print("[RuffScanner] 'ruff' executable not found in PATH. Skipping.")
            return findings

        try:
            # Run ruff check over target path, output to JSON format
            result = subprocess.run(
                ["ruff", "check", "--format", "json", repo_path],
                capture_output=True,
                text=True,
                check=False
            )
            
            if not result.stdout.strip():
                return findings
                
            data = json.loads(result.stdout)
            for issue in data:
                full_path = issue.get("filename", "")
                rel_path = os.path.relpath(full_path, repo_path) if os.path.isabs(full_path) else full_path
                
                # Check code to determine type
                code = issue.get("code", "")
                is_bug = code.startswith("E9") or code.startswith("F") or "syntax" in issue.get("message", "").lower()
                category = "bugs" if is_bug else "codeSmells"
                
                # Normalize severity
                severity = "CRITICAL" if is_bug else "MINOR"
                
                findings.append(Finding(
                    title=issue.get("message", "Lint Issue"),
                    description=f"Rule Code: {code}\nLocation: Col {issue.get('location', {}).get('column', 1)}",
                    file_path=rel_path,
                    line_number=int(issue.get("location", {}).get("row", 1)),
                    severity=severity,
                    category=category
                ))
        except Exception as e:
            print(f"[RuffScanner] Scan encountered an error: {e}")
            
        return findings
