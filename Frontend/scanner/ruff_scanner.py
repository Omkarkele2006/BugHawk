import json
import subprocess
import os
import sys
import importlib.util
from typing import List
from .base import BaseScanner, Finding, map_severity

class RuffScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        
        # Check module availability
        if importlib.util.find_spec("ruff") is None:
            raise RuntimeError("Ruff package is not installed or available in the current Python environment.")

        # Get styling check settings from the current user
        select_rules = "E,F,W"  # pep8 (default)
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                style = current_user.settings_style
                if style == "google":
                    select_rules = "E,F,W,D,I"
                elif style == "airbnb":
                    select_rules = "E,F,W,PL,C90"
        except Exception:
            pass

        try:
            result = subprocess.run(
                [sys.executable, "-m", "ruff", "check", "--select", select_rules, "--format", "json", repo_path],
                capture_output=True,
                text=True,
                check=False
            )
            
            stdout = result.stdout.strip()
            if not stdout:
                return findings
                
            data = json.loads(stdout)
            for issue in data:
                full_path = issue.get("filename", "")
                rel_path = os.path.relpath(full_path, repo_path) if os.path.isabs(full_path) else full_path
                
                code = issue.get("code", "")
                is_bug = code.startswith("E9") or code.startswith("F") or "syntax" in issue.get("message", "").lower()
                category = "bugs" if is_bug else "codeSmells"
                
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
            # Raise the exception so ScanManager captures the exact failure details
            raise RuntimeError(f"Ruff execution encountered an error: {e}")
            
        return findings
