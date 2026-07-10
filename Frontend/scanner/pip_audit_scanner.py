import json
import subprocess
import os
import sys
import importlib.util
from typing import List
from .base import BaseScanner, Finding, map_severity

class PipAuditScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        
        # Check module availability
        if importlib.util.find_spec("pip_audit") is None:
            raise RuntimeError("pip-audit package is not installed or available in the current Python environment.")

        req_files = []
        for root, dirs, files in os.walk(repo_path):
            if any(v in root.replace(os.sep, "/") for v in ["/venv", "/.venv", "/env", "/__pycache__"]):
                continue
            for file in files:
                if file == "requirements.txt" or (file.endswith(".txt") and "requirement" in file.lower()):
                    req_files.append(os.path.join(root, file))

        if not req_files:
            return findings

        for req_file in req_files:
            rel_req_path = os.path.relpath(req_file, repo_path)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip_audit", "-r", req_file, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                stdout = result.stdout.strip()
                if not stdout:
                    continue
                    
                data = json.loads(stdout)
                
                dep_lines = {}
                try:
                    with open(req_file, "r") as f:
                        for idx, line in enumerate(f, 1):
                            cleaned_line = line.strip().lower()
                            if not cleaned_line or cleaned_line.startswith("#"):
                                continue
                            package_name = cleaned_line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
                            if package_name:
                                dep_lines[package_name] = idx
                except Exception as e:
                    print(f"[PipAuditScanner] Failed to parse lines of requirements file: {e}")

                dependencies = data.get("dependencies", []) if isinstance(data, dict) else data
                
                for dep in dependencies:
                    name = dep.get("name", "").lower()
                    version = dep.get("version", "")
                    vulns = dep.get("vulns", [])
                    
                    if not vulns:
                        continue
                        
                    line_num = dep_lines.get(name, 1)
                    
                    for vuln in vulns:
                        vuln_id = vuln.get("id", "N/A")
                        fix_versions = vuln.get("fix_versions", [])
                        
                        rec_fix = f"Upgrade package to safe version(s): {', '.join(fix_versions)}." if fix_versions else "Upgrade package to the latest stable release."
                        recommendation = f"Identify alternative dependencies or apply suggested update. {rec_fix}"
                        
                        severity = map_severity("CRITICAL")
                        
                        findings.append(Finding(
                            scanner="pip-audit",
                            category="security",
                            severity=severity,
                            file=rel_req_path,
                            line=line_num,
                            rule_id=vuln_id,
                            title=f"Vulnerable dependency '{name}' ({vuln_id})",
                            description=(
                                f"Package '{name}' version {version} contains vulnerability: {vuln.get('description', 'N/A')}"
                            ),
                            recommendation=recommendation,
                            confidence="HIGH"
                        ))
            except Exception as e:
                # Raise the exception so ScanManager captures the exact failure details
                raise RuntimeError(f"pip-audit execution failed on {rel_req_path}: {e}")
                
        return findings
