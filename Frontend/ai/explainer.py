import os
import json
import requests
from typing import List, Dict
from .base import FindingExplainer, Explanation, Finding
from .templates import get_fallback_explanation

GEMINI_MODEL_NAME = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')


class BHAIFindingExplainer(FindingExplainer):
    def __init__(self):
        # Allow custom backend FastAPI url or read from environment
        self.backend_url = os.environ.get("BUGHAWK_BACKEND_URL", "http://localhost:8000/submit")
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY")

    def explain_finding(self, finding: Finding) -> Explanation:
        # Get settings from current logged-in user
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
        if system_prompt:
            prompt += f"Custom System Instructions to follow:\n{system_prompt}\n\n"
            
        prompt += (
            f"Respond with a strict raw JSON object (and nothing else) containing the following string keys:\n"
            f"1. \"explanation\": a clear details summary explaining the issue\n"
            f"2. \"why_it_matters\": why this coding pattern is problematic\n"
            f"3. \"possible_impact\": what can go wrong if this is left in production\n"
            f"4. \"recommended_fix\": {fix_instruction}\n"
            f"5. \"developer_friendly_summary\": a single-sentence friendly overview\n"
        )

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
                
                # Execute request with 5 seconds timeout
                response = requests.post(gemini_url, headers=headers, json=payload, timeout=5)
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
            except Exception as e:
                print(f"[BHAIFindingExplainer] Gemini API call failed: {e}. Falling back.")

        # 2. Try Local FastAPI backend if available
        if os.environ.get("BUGHAWK_USE_LOCAL_BACKEND") == "True":
            try:
                headers = {"Content-Type": "application/json"}
                payload = {"query": prompt, "max_tokens": 1024}
                response = requests.post(self.backend_url, headers=headers, json=payload, timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    raw_text = result.get("response", "").strip()
                    # Strip markdown blocks if returned
                    if raw_text.startswith("```"):
                        lines = raw_text.splitlines()
                        if lines[0].startswith("```json"):
                            raw_text = "\n".join(lines[1:-1])
                        else:
                            raw_text = "\n".join(lines[1:-1])
                    parsed = json.loads(raw_text)
                    return Explanation(
                        explanation=parsed.get("explanation", ""),
                        why_it_matters=parsed.get("why_it_matters", ""),
                        possible_impact=parsed.get("possible_impact", ""),
                        recommended_fix=parsed.get("recommended_fix", ""),
                        developer_friendly_summary=parsed.get("developer_friendly_summary", "")
                    )
            except Exception as e:
                print(f"[BHAIFindingExplainer] Local backend call failed: {e}. Falling back.")

        # 3. Fallback to templates if API keys are missing or calls failed
        return get_fallback_explanation(finding.category, finding.rule_id, finding.title, finding.description)

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
        """Generates a structured executive summary from findings statistics using LLMs with a static fallback."""
        sec_count = category_counts.get("security", 0)
        bug_count = category_counts.get("bugs", 0)
        smell_count = category_counts.get("codeSmells", 0)
        perf_count = category_counts.get("performance", 0)
        
        # Get settings from current logged-in user
        system_prompt = ""
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                system_prompt = current_user.settings_system_prompt
        except Exception:
            pass

        # Include top findings in prompt to keep the AI summary representative
        key_findings_str = "\n".join([f"- {f.title} (Scanner: {f.scanner}, File: {f.file}:{f.line})" for f in findings[:5]])
        
        prompt = (
            f"You are BugHawk AI. Write a concise executive summary for a repository security and code scan.\n\n"
            f"Scan Statistics:\n"
            f"- Project Name: {project_name}\n"
            f"- Overall Grade: {grade} (Status: {status})\n"
            f"- Total Findings: {total_count}\n"
            f"  * Security: {sec_count}\n"
            f"  * Bugs: {bug_count}\n"
            f"  * Code Smells: {smell_count}\n"
            f"  * Performance: {perf_count}\n\n"
            f"Key Findings to note:\n"
            f"{key_findings_str}\n\n"
        )
        if system_prompt:
            prompt += f"Custom System Instructions to follow:\n{system_prompt}\n\n"

        prompt += (
            f"Write a professional summary suitable for a CTO or engineering lead. "
            f"Summarize the findings, highlight major risks (e.g. security exposures or complexity), "
            f"and propose immediate remediation steps. Limit the summary to exactly 4 sentences. Do not use bullet points or code blocks."
        )

        # 1. Try Gemini API
        if self.gemini_api_key:
            try:
                gemini_url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{GEMINI_MODEL_NAME}:generateContent?key={self.gemini_api_key}"
                )
                headers = {"Content-Type": "application/json"}
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                
                response = requests.post(gemini_url, headers=headers, json=payload, timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    summary_text = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    if summary_text:
                        return summary_text
            except Exception as e:
                print(f"[BHAIFindingExplainer] Executive summary Gemini call failed: {e}. Falling back.")

        # 2. Try Local FastAPI
        if os.environ.get("BUGHAWK_USE_LOCAL_BACKEND") == "True":
            try:
                headers = {"Content-Type": "application/json"}
                payload = {"query": prompt, "max_tokens": 512}
                response = requests.post(self.backend_url, headers=headers, json=payload, timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    summary_text = result.get("response", "").strip()
                    if summary_text:
                        return summary_text
            except Exception as e:
                print(f"[BHAIFindingExplainer] Executive summary local call failed: {e}. Falling back.")

        # 3. Static fallback
        rem_msg = "Immediate refactoring and updates are advised." if total_count > 0 else "No actions needed."
        return (
            f"The BugHawk AI engine completed an automated audit of the project '{project_name}'. "
            f"A total of {total_count} findings were identified, comprising {sec_count} security issues, "
            f"{bug_count} logic bugs, and {smell_count} code smells. This code quality corresponds "
            f"to an overall grade rank of {grade} ({status}). {rem_msg}"
        )
