import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding, map_severity

class RadonScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("radon"):
            print("[RadonScanner] 'radon' executable not found in PATH. Skipping.")
            return findings

        try:
            result = subprocess.run(
                ["radon", "cc", "-j", "-s", repo_path],
                capture_output=True,
                text=True,
                check=False
            )
            
            if not result.stdout.strip():
                return findings
                
            data = json.loads(result.stdout)
            for file_key, blocks in data.items():
                rel_path = os.path.relpath(file_key, repo_path) if os.path.isabs(file_key) else file_key
                
                for block in blocks:
                    rank = block.get("rank", "A")
                    if rank in ["A", "B"]:
                        continue
                        
                    complexity = block.get("complexity", 1)
                    name = block.get("name", "N/A")
                    block_type = block.get("type", "function")
                    lineno = int(block.get("lineno", 1))
                    
                    # Centralized severity mapping
                    severity = map_severity(rank)
                    
                    recommendation = (
                        f"Reduce the cyclomatic complexity of {block_type} '{name}'. "
                        "Refactor nested if-else structures, break compound logical operators, "
                        "or extract logical branches into distinct sub-functions."
                    )
                    
                    findings.append(Finding(
                        scanner="radon",
                        category="codeSmells",
                        severity=severity,
                        file=rel_path,
                        line=lineno,
                        rule_id=f"RADON-{rank}",
                        title=f"Complex {block_type} '{name}'",
                        description=f"Complexity metric is {complexity} (Rank {rank}). Code is convoluted and prone to regression.",
                        recommendation=recommendation,
                        confidence="HIGH"
                    ))
        except Exception as e:
            print(f"[RadonScanner] Scan encountered an error: {e}")
            
        return findings
