import json
import subprocess
import os
import sys
import importlib.util
from typing import List
from .base import BaseScanner, Finding, map_severity

# Mapping of specific Bandit test IDs to standard titles, severities, categories and recommendations
BANDIT_RULE_MAPS = {
    "B101": {
        "title": "Use of assert statements detected in source",
        "severity": "MINOR",
        "category": "codeSmells",
        "recommendation": "Remove assert statements or replace with robust conditional exception raising for production checks."
    },
    "B102": {
        "title": "Insecure exec() command utilization",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Avoid using exec() dynamically to prevent remote code injection vulnerabilities."
    },
    "B103": {
        "title": "Insecure permission configurations for files",
        "severity": "MAJOR",
        "category": "security",
        "recommendation": "Set secure directory/file permission masks (e.g. 0o600 or 0o700) using chmod."
    },
    "B104": {
        "title": "Hardcoded bind listener to all network interfaces (0.0.0.0)",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Bind connection socket listeners specifically to loopback (127.0.0.1) or safe private network targets."
    },
    "B105": {
        "title": "Hardcoded password/token credential string identified",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Remove plaintext security tokens or credentials. Rely on external environment configurations or secure vaults."
    },
    "B108": {
        "title": "Hardcoded temporary directory destination usage",
        "severity": "MINOR",
        "category": "codeSmells",
        "recommendation": "Use secure system utilities such as Python's tempfile module to allocate directories safely."
    },
    "B301": {
        "title": "Insecure serialization/deserialization via pickle module",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Avoid loading untrusted binary data using pickle. Standardize secure transfer protocols (JSON, YAML, or Protocol Buffers)."
    },
    "B307": {
        "title": "Insecure evaluation using eval()",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Avoid eval() execution. Use safer parsers like ast.literal_eval if evaluating literals."
    },
    "B404": {
        "title": "Process execution module imported (subprocess)",
        "severity": "INFO",
        "category": "codeSmells",
        "recommendation": "Verify all process spawning logic and ensure external parameters are not passed unsanitized."
    },
    "B608": {
        "title": "Possible SQL injection vulnerability via string concatenation",
        "severity": "CRITICAL",
        "category": "security",
        "recommendation": "Construct queries using parameterized statement inputs, db api bindings, or secure ORMs."
    }
}

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
                
                test_id = issue.get("test_id", "N/A")
                
                # 1. Check module rule mappings
                rule_config = BANDIT_RULE_MAPS.get(test_id)
                if rule_config:
                    title = rule_config["title"]
                    severity = map_severity(rule_config["severity"])
                    category = rule_config["category"]
                    recommendation = rule_config["recommendation"]
                # 2. Check process execution wildcard mappings (B601-B607)
                elif test_id.startswith("B6") and test_id != "B608":
                    title = "Subprocess start with potential shell command vulnerability"
                    severity = map_severity("MAJOR")
                    category = "security"
                    recommendation = "Avoid shell=True process execution. Pass commands as standard arrays and specify absolute bin path."
                # 3. Default fallback values
                else:
                    title = issue.get("issue_text", "Security Vulnerability")
                    severity = map_severity(issue.get("issue_severity", "LOW"))
                    category = "security"
                    recommendation = (
                        "Avoid using insecure functions or importing vulnerable symbols. "
                        "Validate and sanitize inputs."
                    )
                
                findings.append(Finding(
                    scanner="bandit",
                    category=category,
                    severity=severity,
                    file=rel_path,
                    line=int(issue.get("line_number", 1)),
                    rule_id=test_id,
                    title=title,
                    description=f"Vulnerability Details:\n{issue.get('code', '')}",
                    recommendation=recommendation,
                    confidence=issue.get("issue_confidence", "HIGH").upper()
                ))
        except Exception as e:
            # Raise the exception so ScanManager captures the exact failure details
            raise RuntimeError(f"Bandit execution encountered an error: {e}")
            
        return findings
