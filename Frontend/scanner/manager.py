import os
import uuid
import shutil
import subprocess
from typing import List, Dict, Any
from datetime import datetime, timezone

from .base import Finding
from .bandit_scanner import BanditScanner
from .ruff_scanner import RuffScanner
from .radon_scanner import RadonScanner
from .pip_audit_scanner import PipAuditScanner
from .report import Report, FindingWithExplanation
from ai.explainer import BHAIFindingExplainer

class ScanManager:
    def __init__(self):
        # Instantiate available concrete scanners
        self.scanners = [
            BanditScanner(),
            RuffScanner(),
            RadonScanner(),
            PipAuditScanner()
        ]

    def _clone_repository(self, repo_url: str, dest_path: str) -> bool:
        """Clones a Git repository to the target destination path using depth=1."""
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, dest_path],
                capture_output=True,
                text=True,
                check=True,
                timeout=15
            )
            return True
        except subprocess.TimeoutExpired as te:
            print(f"[ScanManager] Git clone timed out for {repo_url}: {te}")
            raise ValueError("Git repository clone timed out.")
        except subprocess.CalledProcessError as cpe:
            print(f"[ScanManager] Git clone process failed for {repo_url}. Stderr: {cpe.stderr}")
            raise ValueError(f"Git repository clone failed: {cpe.stderr.strip() if cpe.stderr else 'Unknown error'}")
        except Exception as e:
            print(f"[ScanManager] Failed to clone {repo_url}: {e}")
            raise ValueError(f"Failed to clone repository: {str(e)}")

    def _cleanup_repository(self, path: str):
        """Clean up the cloned repository files recursively, handling read-only git files."""
        if not os.path.exists(path):
            return

        def remove_readonly(func, file_path, excinfo):
            import stat
            try:
                os.chmod(file_path, stat.S_IWRITE)
                func(file_path)
            except Exception as e:
                print(f"[ScanManager] Failed to clean up file {file_path}: {e}")

        try:
            shutil.rmtree(path, onerror=remove_readonly)
        except Exception as e:
            print(f"[ScanManager] Directory cleanup error for {path}: {e}")

    def run_analysis(self, repo_url: str) -> Report:
        """Clones a repository, runs all scanners, aggregates findings, and returns a structured Report."""
        # Setup temporary directories under Flask's ignored instance path
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        temp_root = os.path.join(base_dir, "instance", "temp")
        os.makedirs(temp_root, exist_ok=True)

        scan_id = str(uuid.uuid4())
        dest_path = os.path.join(temp_root, scan_id)

        findings: List[Finding] = []
        project_name = "Unknown Project"

        try:
            # Extract project name from URL
            cleaned_url = repo_url.rstrip("/")
            if cleaned_url.endswith(".git"):
                cleaned_url = cleaned_url[:-4]
            project_name = cleaned_url.split("/")[-1]
        except Exception:
            pass

        try:
            print(f"[ScanManager] Beginning checkout of {repo_url} into {dest_path}")
            self._clone_repository(repo_url, dest_path)

            # Run all scanners
            for scanner in self.scanners:
                try:
                    scanner_findings = scanner.scan(dest_path)
                    print(f"[ScanManager] {scanner.__class__.__name__} found {len(scanner_findings)} issues.")
                    findings.extend(scanner_findings)
                except Exception as ex:
                    print(f"[ScanManager] Scanner {scanner.__class__.__name__} failed: {ex}")

        finally:
            print(f"[ScanManager] Cleaning up directory {dest_path}")
            self._cleanup_repository(dest_path)

        # Build detailed findings with AI explanations
        explainer = BHAIFindingExplainer()
        findings_with_explanations: List[FindingWithExplanation] = []
        
        for finding in findings:
            try:
                explanation = explainer.explain_finding(finding)
            except Exception as e:
                print(f"[ScanManager] Failed to explain finding {finding.rule_id}: {e}")
                from ai.templates import get_fallback_explanation
                explanation = get_fallback_explanation(finding.category, finding.rule_id, finding.title, finding.description)
                
            findings_with_explanations.append(FindingWithExplanation(
                finding=finding,
                explanation=explanation
            ))

        # Compile statistics and build the unified Report
        return self._generate_report(project_name, repo_url, findings_with_explanations)

    def _generate_report(self, project_name: str, repo_url: str, findings: List[FindingWithExplanation]) -> Report:
        """Aggregates standard metrics, runs severity classification and constructs the final Report."""
        issue_counts_by_category = {"security": 0, "bugs": 0, "performance": 0, "codeSmells": 0}
        issue_counts_by_severity = {"CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
        
        # Health score calculations
        score_value = 100.0

        for fe in findings:
            f = fe.finding
            
            # Category counts
            cat = f.category
            if cat in issue_counts_by_category:
                issue_counts_by_category[cat] += 1
            else:
                issue_counts_by_category["codeSmells"] += 1

            # Severity counts
            sev = f.severity.upper()
            if sev in issue_counts_by_severity:
                issue_counts_by_severity[sev] += 1
            else:
                issue_counts_by_severity["INFO"] += 1

            # Calculate health score deductions
            if sev == "CRITICAL":
                score_value -= 10
            elif sev == "MAJOR":
                score_value -= 5
            elif sev == "MINOR":
                score_value -= 1
            else:
                score_value -= 0.5

        # Lower bound health score
        score_value = max(0.0, score_value)

        # Grade mapping
        if score_value > 90:
            grade = "A+"
        elif score_value > 80:
            grade = "A"
        elif score_value > 70:
            grade = "B+"
        elif score_value > 60:
            grade = "B"
        elif score_value > 50:
            grade = "C"
        else:
            grade = "F"

        status = "Good" if score_value > 65 else "Needs Improvement"

        # Determine executed scanners
        tools_executed = []
        for scanner in self.scanners:
            name = scanner.__class__.__name__
            if name == "BanditScanner" and shutil.which("bandit"):
                tools_executed.append("bandit")
            elif name == "RuffScanner" and shutil.which("ruff"):
                tools_executed.append("ruff")
            elif name == "RadonScanner" and shutil.which("radon"):
                tools_executed.append("radon")
            elif name == "PipAuditScanner" and shutil.which("pip-audit"):
                tools_executed.append("pip-audit")

        # Sort prioritized findings (CRITICAL first, then MAJOR, then MINOR)
        severity_rank = {"CRITICAL": 0, "MAJOR": 1, "MINOR": 2, "INFO": 3}
        sorted_findings = sorted(findings, key=lambda fe: severity_rank.get(fe.finding.severity.upper(), 4))
        prioritized_findings = sorted_findings[:3]

        # Generate Executive Summary using BHAIFindingExplainer
        explainer = BHAIFindingExplainer()
        raw_findings_list = [fe.finding for fe in findings]
        try:
            executive_summary = explainer.generate_executive_summary(
                project_name=project_name,
                findings=raw_findings_list,
                grade=grade,
                status=status
            )
        except Exception as e:
            print(f"[ScanManager] Failed to generate executive summary: {e}")
            executive_summary = (
                f"Static analysis of project '{project_name}' concluded with an overall rank score of {grade} ({status}). "
                f"A total of {len(findings)} issues were detected by automated audit tools."
            )

        return Report(
            project_name=project_name,
            repo_url=repo_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tools_executed=tools_executed,
            issue_counts_by_severity=issue_counts_by_severity,
            issue_counts_by_category=issue_counts_by_category,
            health_score_grade=grade,
            health_score_status=status,
            health_score_numeric=score_value,
            findings=findings,
            prioritized_findings=prioritized_findings,
            executive_summary=executive_summary
        )
