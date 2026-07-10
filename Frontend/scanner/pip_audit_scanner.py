import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding

class PipAuditScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("pip-audit"):
            # pip-audit is not installed locally; skip scan gracefully
            print("[PipAuditScanner] 'pip-audit' executable not found in PATH. Skipping.")
            return findings

        # Find all requirements.txt files recursively
        req_files = []
        for root, dirs, files in os.walk(repo_path):
            # Ignore virtual environments if checked out locally
            if any(v in root.replace(os.sep, "/") for v in ["/venv", "/.venv", "/env", "/__pycache__"]):
                continue
            for file in files:
                if file == "requirements.txt" or (file.endswith(".txt") and "requirement" in file.lower()):
                    req_files.append(os.path.join(root, file))

        # If no requirements files found, we can't scan dependencies via pip-audit
        if not req_files:
            return findings

        for req_file in req_files:
            rel_req_path = os.path.relpath(req_file, repo_path)
            try:
                # Run pip-audit on requirements file
                result = subprocess.run(
                    ["pip-audit", "-r", req_file, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                # Check for output
                stdout = result.stdout.strip()
                if not stdout:
                    continue
                    
                data = json.loads(stdout)
                
                # Find exact line numbers of dependencies in the requirements file
                dep_lines = {}
                try:
                    with open(req_file, "r") as f:
                        for idx, line in enumerate(f, 1):
                            cleaned_line = line.strip().lower()
                            if not cleaned_line or cleaned_line.startswith("#"):
                                continue
                            # Extract package name (up to ==, >=, etc.)
                            package_name = cleaned_line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
                            if package_name:
                                dep_lines[package_name] = idx
                except Exception as e:
                    print(f"[PipAuditScanner] Failed to parse lines of requirements file: {e}")

                # Process vulnerabilities
                # Note: pip-audit returns either a list of dependencies or a dict depending on the exact version/format.
                # Standard json format is a dict with "dependencies" key:
                # { "dependencies": [ { "name": "...", "version": "...", "vulns": [...] } ] }
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
                        fix_versions = ", ".join(vuln.get("fix_versions", []))
                        fix_text = f" Fix versions: {fix_versions}." if fix_versions else ""
                        
                        findings.append(Finding(
                            title=f"Vulnerability in dependency '{name}' ({vuln_id})",
                            description=(
                                f"Dependency: {name} (version {version}).{fix_text}\n"
                                f"Description: {vuln.get('description', 'N/A')}"
                            ),
                            file_path=rel_req_path,
                            line_number=line_num,
                            severity="CRITICAL",
                            category="security"
                        ))
            except Exception as e:
                print(f"[PipAuditScanner] Scan encountered an error on {rel_req_path}: {e}")
                
        return findings
