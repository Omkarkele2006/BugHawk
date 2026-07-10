import json
import subprocess
import os
import shutil
from typing import List
from .base import BaseScanner, Finding

class RadonScanner(BaseScanner):
    def scan(self, repo_path: str) -> List[Finding]:
        findings = []
        if not shutil.which("radon"):
            # Radon is not installed locally; skip scan gracefully
            print("[RadonScanner] 'radon' executable not found in PATH. Skipping.")
            return findings

        try:
            # Run radon complexity checks (-j is JSON, -s displays complexity value)
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
                # Radon returns a dictionary where keys are file paths
                rel_path = os.path.relpath(file_key, repo_path) if os.path.isabs(file_key) else file_key
                
                for block in blocks:
                    rank = block.get("rank", "A")
                    # Skip rank A and B (good code complexity scores)
                    if rank in ["A", "B"]:
                        continue
                        
                    complexity = block.get("complexity", 1)
                    name = block.get("name", "N/A")
                    block_type = block.get("type", "function")
                    lineno = int(block.get("lineno", 1))
                    
                    # Normalize severity
                    severity = "CRITICAL" if rank in ["E", "F"] else "MAJOR"
                    
                    findings.append(Finding(
                        title=f"High Cyclomatic Complexity in {block_type} '{name}' (Rank {rank})",
                        description=f"Complexity value is {complexity}. High complexity indicates hard-to-maintain code.",
                        file_path=rel_path,
                        line_number=lineno,
                        severity=severity,
                        category="codeSmells"
                    ))
        except Exception as e:
            print(f"[RadonScanner] Scan encountered an error: {e}")
            
        return findings
