import os
import json
import requests
import time
from typing import List, Dict, Tuple
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from .base import FindingExplainer, Explanation, Finding
from .templates import get_fallback_explanation

# Create global persistent session for Gemini Explainer
explainer_session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    raise_on_status=False
)
explainer_session.mount("https://", HTTPAdapter(max_retries=retries))

GEMINI_MODEL_NAME = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')
SKIP_AI_EXPLANATIONS = os.environ.get("SKIP_AI_EXPLANATIONS", "False").lower() == "true"
GEMINI_READ_TIMEOUT = int(os.environ.get("GEMINI_READ_TIMEOUT", 30))
GEMINI_CONNECT_TIMEOUT = int(os.environ.get("GEMINI_CONNECT_TIMEOUT", 10))
TIMEOUT_VAL = (GEMINI_CONNECT_TIMEOUT, GEMINI_READ_TIMEOUT)


class BHAIFindingExplainer(FindingExplainer):
    def __init__(self):
        # Allow custom backend FastAPI url or read from environment
        self.backend_url = os.environ.get("BUGHAWK_BACKEND_URL", "http://localhost:8000/submit")
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY")

    def explain_finding(self, finding: Finding) -> Explanation:
        """Fallback compatibility method for singular explanations."""
        if SKIP_AI_EXPLANATIONS:
            return get_fallback_explanation(finding.category, finding.rule_id, finding.title, finding.description)

        # Prompt construction asking for strict JSON structure
        prompt = (
            f"You are BugHawk AI. Analyze the following static code scan finding and explain it.\n\n"
            f"Finding Details:\n"
            f"- Tool/Scanner: {finding.scanner}\n"
            f"- Rule ID: {finding.rule_id}\n"
            f"- Category: {finding.category}\n"
            f"- Severity: {finding.severity}\n"
            f"- File: {finding.file}:{finding.line}\n"
            f"- Issue Title: {finding.title}\n"
            f"- Issue Description: {finding.description}\n\n"
        )
        prompt += (
            f"Respond with a strict raw JSON object containing the following keys:\n"
            f"\"explanation\", \"why_it_matters\", \"possible_impact\", \"recommended_fix\", \"developer_friendly_summary\"."
        )

        if self.gemini_api_key:
            try:
                gemini_url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{GEMINI_MODEL_NAME}:generateContent?key={self.gemini_api_key}"
                )
                headers = {"Content-Type": "application/json"}
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "responseMimeType": "application/json"
                    }
                }
                
                response = explainer_session.post(gemini_url, headers=headers, json=payload, timeout=TIMEOUT_VAL)
                if response.status_code == 200:
                    result = response.json()
                    raw_text = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    parsed = json.loads(raw_text)
                    return Explanation(
                        explanation=parsed.get("explanation", ""),
                        why_it_matters=parsed.get("why_it_matters", ""),
                        possible_impact=parsed.get("possible_impact", ""),
                        recommended_fix=parsed.get("recommended_fix", ""),
                        developer_friendly_summary=parsed.get("developer_friendly_summary", "")
                    )
            except Exception:
                pass

        return get_fallback_explanation(finding.category, finding.rule_id, finding.title, finding.description)

    def explain_findings_batch(
        self, findings: List[Finding], project_name: str, grade: str, status: str,
        total_count: int, category_counts: Dict[str, int]
    ) -> Tuple[Dict[Tuple[str, str], Explanation], str]:
        """Sends a single Gemini API request to batch explain all findings and generate the executive summary."""
        explanations = {}
        
        # Calculate categories
        sec_count = category_counts.get("security", 0)
        bug_count = category_counts.get("bugs", 0)
        smell_count = category_counts.get("codeSmells", 0)
        perf_count = category_counts.get("performance", 0)
        
        # Retrieve user settings
        auto_fix = True
        system_prompt = ""
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                auto_fix = current_user.settings_auto_fix
                system_prompt = current_user.settings_system_prompt
        except Exception:
            pass

        fix_instruction = "provide a complete code replacement or patch demonstrating the secure coding fix." if auto_fix else "provide high-level explanation of the remediation steps in plain English without including code blocks or code patches."

        # Static fallback summary if calls fail
        rem_msg = "Immediate refactoring and updates are advised." if total_count > 0 else "No actions needed."
        fallback_summary = (
            f"The BugHawk AI engine completed an automated audit of the project '{project_name}'. "
            f"A total of {total_count} findings were identified, comprising {sec_count} security issues, "
            f"{bug_count} logic bugs, and {smell_count} code smells. This code quality corresponds "
            f"to an overall grade rank of {grade} ({status}). {rem_msg}"
        )

        if SKIP_AI_EXPLANATIONS or not findings:
            print(f"[BHAIFindingExplainer] Gemini batch request skipped (SKIP_AI_EXPLANATIONS={SKIP_AI_EXPLANATIONS} or empty findings).")
            return explanations, fallback_summary

        # Format findings list for prompt
        findings_json = []
        for idx, f in enumerate(findings):
            findings_json.append({
                "index": idx,
                "rule_id": f.rule_id,
                "file": f.file,
                "scanner": f.scanner,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description
            })

        prompt = (
            f"You are BugHawk AI. Analyze the following static code scan findings for the project '{project_name}' and explain them.\n\n"
            f"Scan Statistics:\n"
            f"- Project Name: {project_name}\n"
            f"- Overall Grade: {grade} (Status: {status})\n"
            f"- Total Findings: {total_count}\n"
            f"  * Security: {sec_count}\n"
            f"  * Bugs: {bug_count}\n"
            f"  * Code Smells: {smell_count}\n"
            f"  * Performance: {perf_count}\n\n"
            f"Here is the list of findings to explain in JSON format:\n"
            f"{json.dumps(findings_json, indent=2)}\n\n"
        )
        if system_prompt:
            prompt += f"Custom System Instructions to follow:\n{system_prompt}\n\n"

        prompt += (
            f"Respond with a strict raw JSON object (and nothing else) containing exactly two keys:\n"
            f"1. \"explanations\": a JSON array of objects (one per input finding, keeping the same order). Each object must contain these string keys:\n"
            f"   - \"rule_id\": the rule_id of the finding (exactly matched)\n"
            f"   - \"file\": the file path of the finding (exactly matched)\n"
            f"   - \"explanation\": a clear details summary explaining the issue\n"
            f"   - \"why_it_matters\": why this coding pattern is problematic\n"
            f"   - \"possible_impact\": what can go wrong if left in production\n"
            f"   - \"recommended_fix\": {fix_instruction}\n"
            f"   - \"developer_friendly_summary\": a single-sentence friendly overview\n"
            f"2. \"executive_summary\": a professional summary text suitable for a CTO or engineering lead, summarizing findings, highlighting risks, and proposing remediation steps. Limit the summary to exactly 4 sentences. Do not use bullet points or code blocks.\n"
        )

        print(f"Gemini batch request started")
        print(f"Findings in batch: {len(findings)}")

        # 1. Try Gemini API first if key exists
        if self.gemini_api_key:
            try:
                gemini_url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{GEMINI_MODEL_NAME}:generateContent?key={self.gemini_api_key}"
                )
                headers = {"Content-Type": "application/json"}
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "responseMimeType": "application/json"
                    }
                }
                
                response = explainer_session.post(gemini_url, headers=headers, json=payload, timeout=TIMEOUT_VAL)
                if response.status_code == 200:
                    result = response.json()
                    raw_text = r = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    parsed = json.loads(raw_text)
                    
                    parsed_explanations = parsed.get("explanations", [])
                    for item in parsed_explanations:
                        r_id = item.get("rule_id")
                        f_file = item.get("file")
                        explanations[(r_id, f_file)] = Explanation(
                            explanation=item.get("explanation", ""),
                            why_it_matters=item.get("why_it_matters", ""),
                            possible_impact=item.get("possible_impact", ""),
                            recommended_fix=item.get("recommended_fix", ""),
                            developer_friendly_summary=item.get("developer_friendly_summary", "")
                        )
                    
                    executive_summary = parsed.get("executive_summary", fallback_summary)
                    print(f"Batch request succeeded")
                    return explanations, executive_summary
                else:
                    reason = f"HTTP {response.status_code}"
                    print(f"Gemini batch request failed: {reason}")
            except Exception as e:
                print(f"Gemini batch request failed: {str(e)}")

        print(f"Falling back to local explanations.")
        return explanations, fallback_summary

    def explain_findings(self, findings: List[Finding]) -> Dict[str, Explanation]:
        explanations = {}
        for finding in findings:
            key = f"{finding.scanner}::{finding.rule_id}::{finding.file}:{finding.line}"
            explanations[key] = self.explain_finding(finding)
        return explanations

    def generate_executive_summary(
        self, project_name: str, findings: List[Finding], grade: str, status: str,
        total_count: int, category_counts: Dict[str, int]
    ) -> str:
        """Legacy fallback/compatibility method."""
        rem_msg = "Immediate refactoring and updates are advised." if total_count > 0 else "No actions needed."
        return (
            f"The BugHawk AI engine completed an automated audit of the project '{project_name}'. "
            f"A total of {total_count} findings were identified, comprising {category_counts.get('security', 0)} security issues, "
            f"{category_counts.get('bugs', 0)} logic bugs, and {category_counts.get('codeSmells', 0)} code smells. This code quality corresponds "
            f"to an overall grade rank of {grade} ({status}). {rem_msg}"
        )
