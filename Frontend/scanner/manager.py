import os
import uuid
import shutil
import subprocess
import time
from typing import List, Dict, Any
from datetime import datetime, timezone

from .base import Finding
from .bandit_scanner import BanditScanner
from .ruff_scanner import RuffScanner
from .radon_scanner import RadonScanner
from .pip_audit_scanner import PipAuditScanner
from .report import Report, FindingWithExplanation
from .job import ScanJob
from ai.explainer import BHAIFindingExplainer

class ScanManager:
    def __init__(self):
        # Configurable maximum limit of explained findings
        self.max_explained_findings = 50
        
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
        """Clean up the cloned repository files recursively, handling read-only git files with retry logic for Windows locks."""
        if not os.path.exists(path):
            return

        import stat
        def remove_readonly(func, file_path, excinfo):
            try:
                os.chmod(file_path, stat.S_IWRITE)
                func(file_path)
            except Exception as e:
                print(f"[ScanManager] Failed to clean up file {file_path}: {e}")

        # Try up to 3 times with a short sleep in case of transient locks
        for attempt in range(3):
            try:
                if os.path.exists(path):
                    shutil.rmtree(path, onerror=remove_readonly)
                print(f"[ScanManager] Cleaned up directory {path} successfully.")
                break
            except Exception as e:
                if attempt == 2:
                    print(f"[ScanManager] Directory cleanup error for {path} after 3 attempts: {e}")
                else:
                    print(f"[ScanManager] Directory cleanup attempt {attempt + 1} failed: {e}. Retrying...")
                    time.sleep(0.5)

    def run_analysis(self, repo_url: str, job: ScanJob = None) -> Report:
        """Clones a repository, runs all scanners, aggregates findings, and returns a structured Report.
        
        If a ScanJob is passed, its status and progress are updated throughout execution.
        """
        # Ensure ScanJob exists
        if job is None:
            job = ScanJob(
                job_id=str(uuid.uuid4()),
                repository_url=repo_url,
                status="PENDING",
                created_at=datetime.now(timezone.utc).isoformat()
            )

        # Transition status to RUNNING
        job.status = "RUNNING"
        job.started_at = datetime.now(timezone.utc).isoformat()
        job.progress = 10

        # Setup temporary directories under Flask's ignored instance path
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        temp_root = os.path.join(base_dir, "instance", "temp")
        os.makedirs(temp_root, exist_ok=True)

        scan_id = str(uuid.uuid4())
        dest_path = os.path.join(temp_root, scan_id)

        findings: List[Finding] = []
        tools_failed: List[str] = []
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
            job.progress = 20
            self._clone_repository(repo_url, dest_path)
            job.progress = 40

            # Run all scanners
            for idx, scanner in enumerate(self.scanners):
                # Map concrete class names to user-friendly linter labels
                tool_name = "bandit"
                if scanner.__class__.__name__ == "RuffScanner":
                    tool_name = "ruff"
                elif scanner.__class__.__name__ == "RadonScanner":
                    tool_name = "radon"
                elif scanner.__class__.__name__ == "PipAuditScanner":
                    tool_name = "pip-audit"
                
                try:
                    scanner_findings = scanner.scan(dest_path)
                    print(f"[ScanManager] {scanner.__class__.__name__} found {len(scanner_findings)} issues.")
                    findings.extend(scanner_findings)
                except Exception as ex:
                    print(f"[ScanManager] Scanner {scanner.__class__.__name__} failed: {ex}")
                    tools_failed.append(tool_name)
                
                # Update scanner progress incrementally (mapping 40% -> 80% range)
                job.progress = 40 + int((idx + 1) / len(self.scanners) * 40)

        except Exception as e:
            # Transition to FAILED state and clean up before re-raising
            job.status = "FAILED"
            job.completed_at = datetime.now(timezone.utc).isoformat()
            job.error_message = str(e)
            self._cleanup_repository(dest_path)
            raise

        finally:
            print(f"[ScanManager] Cleaning up directory {dest_path}")
            self._cleanup_repository(dest_path)

        # Performance Optimization:
        # 1. Deduplicate findings using (scanner, rule_id, file), keeping the earliest occurrence (by line number)
        sorted_by_line = sorted(findings, key=lambda f: f.line)
        deduped_findings: List[Finding] = []
        seen = set()
        for f in sorted_by_line:
            key = (f.scanner, f.rule_id, f.file)
            if key not in seen:
                seen.add(key)
                deduped_findings.append(f)

        # 2. Prioritize findings by severity, then by confidence
        severity_rank = {"CRITICAL": 0, "MAJOR": 1, "MINOR": 2, "INFO": 3}
        confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        
        prioritized_raw_findings = sorted(
            deduped_findings,
            key=lambda f: (
                severity_rank.get(f.severity.upper(), 4),
                confidence_rank.get(f.confidence.upper(), 3)
            )
        )

        # 3. Limit findings for detailed AI explanations
        limit = self.max_explained_findings
        total_findings_count = len(findings)
        findings_to_explain = prioritized_raw_findings[:limit]

        # 4. Generate AI explanations only for the prioritized subset
        job.progress = 90
        explainer = BHAIFindingExplainer()
        findings_with_explanations: List[FindingWithExplanation] = []
        
        for finding in findings_to_explain:
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

        # Compile statistics, build Report, link to Job, and mark COMPLETED
        report = self._generate_report(
            project_name=project_name,
            repo_url=repo_url,
            all_findings=findings,
            findings_with_explanations=findings_with_explanations,
            tools_failed=tools_failed,
            total_raw_count=total_findings_count
        )
        
        job.report = report
        job.status = "COMPLETED"
        job.completed_at = datetime.now(timezone.utc).isoformat()
        job.progress = 100

        return report

    def _generate_report(
        self, project_name: str, repo_url: str, all_findings: List[Finding],
        findings_with_explanations: List[FindingWithExplanation], tools_failed: List[str],
        total_raw_count: int
    ) -> Report:
        """Aggregates standard metrics, runs severity classification and constructs the final Report."""
        from .scoring import HealthScoreEngine

        # Calculate score and grade details via HealthScoreEngine using ALL findings
        scoring_engine = HealthScoreEngine()
        health_score = scoring_engine.calculate(all_findings)

        # Build category counts expected by UI using ALL findings
        issue_counts_by_category = {"security": 0, "bugs": 0, "performance": 0, "codeSmells": 0}
        for f in all_findings:
            cat = f.category
            if cat in issue_counts_by_category:
                issue_counts_by_category[cat] += 1
            else:
                issue_counts_by_category["codeSmells"] += 1

        # Determine executed scanners
        tools_executed = []
        for scanner in self.scanners:
            name = scanner.__class__.__name__
            tool_id = "bandit"
            if name == "RuffScanner":
                tool_id = "ruff"
            elif name == "RadonScanner":
                tool_id = "radon"
            elif name == "PipAuditScanner":
                tool_id = "pip-audit"
                
            if tool_id not in tools_failed:
                tools_executed.append(tool_id)

        # Priority issues (top 3) from the prioritized, explained subset
        prioritized_findings = findings_with_explanations[:3]

        # Generate Executive Summary using BHAIFindingExplainer with only the prioritized subset and overall stats
        explainer = BHAIFindingExplainer()
        prioritized_raw_list = [fe.finding for fe in findings_with_explanations]
        try:
            executive_summary = explainer.generate_executive_summary(
                project_name=project_name,
                findings=prioritized_raw_list,
                grade=health_score.grade,
                status=health_score.status,
                total_count=total_raw_count,
                category_counts=issue_counts_by_category
            )
        except Exception as e:
            print(f"[ScanManager] Failed to generate executive summary: {e}")
            executive_summary = (
                f"Static analysis of project '{project_name}' concluded with an overall rank score of {health_score.grade} ({health_score.status}). "
                f"A total of {total_raw_count} issues were detected by automated audit tools."
            )

        # Inject limits metadata warning to executive summary if findings exceed threshold
        limit = self.max_explained_findings
        if total_raw_count > limit:
            metadata_info = f"[Displaying top {limit} of {total_raw_count} findings]"
            executive_summary = f"{metadata_info}\n\n{executive_summary}"

        # Append execution failure warnings to the executive report if any scanner failed
        if tools_failed:
            executive_summary += f"\n\n[Warning: The following scanners failed or were unavailable: {', '.join(tools_failed)}]"

        # Compile severity counts using ALL findings
        issue_counts_by_severity = {"CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
        for f in all_findings:
            sev = f.severity.upper()
            if sev in issue_counts_by_severity:
                issue_counts_by_severity[sev] += 1
            else:
                issue_counts_by_severity["INFO"] += 1

        return Report(
            project_name=project_name,
            repo_url=repo_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tools_executed=tools_executed,
            issue_counts_by_severity=issue_counts_by_severity,
            issue_counts_by_category=issue_counts_by_category,
            health_score_grade=health_score.grade,
            health_score_status=health_score.status,
            health_score_numeric=health_score.overall_score,
            findings=findings_with_explanations,
            prioritized_findings=prioritized_findings,
            executive_summary=executive_summary,
            tools_failed=tools_failed
        )
