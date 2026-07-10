import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding, map_severity

class RuffScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("ruff"):
            print("[RuffScanner] 'ruff' executable not found in PATH. Skipping.")
            return findings

        try:
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
                
                code = issue.get("code", "")
                is_bug = code.startswith("E9") or code.startswith("F") or "syntax" in issue.get("message", "").lower()
                category = "bugs" if is_bug else "codeSmells"
                
                # Centralized severity mapping
                raw_severity = "CRITICAL" if is_bug else "MINOR"
                severity = map_severity(raw_severity)
                
                recommendation = (
                    f"Refactor the code block violating lint rule '{code}'. "
                    "Ensure correct syntax imports, clean variable usage, and standard formatting conventions."
                )
                
                findings.append(Finding(
                    scanner="ruff",
                    category=category,
                    severity=severity,
                    file=rel_path,
                    line=int(issue.get("location", {}).get("row", 1)),
                    rule_id=code,
                    title=issue.get("message", "Lint Warning"),
                    description=f"Lint rule violation: {issue.get('message', '')}",
                    recommendation=recommendation,
                    confidence="HIGH"
                ))
        except Exception as e:
            print(f"[RuffScanner] Scan encountered an error: {e}")
            
        return findings
