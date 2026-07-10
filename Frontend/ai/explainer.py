import os
import json
import requests
from typing import List, Dict
from .base import FindingExplainer, Explanation, Finding
from .templates import get_fallback_explanation

class BHAIFindingExplainer(FindingExplainer):
    def __init__(self):
        # Allow custom backend FastAPI url or read from environment
        self.backend_url = os.environ.get("BUGHAWK_BACKEND_URL", "http://localhost:8000/submit")
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY")

    def explain_finding(self, finding: Finding) -> Explanation:
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
            f"Respond with a strict raw JSON object (and nothing else) containing the following string keys:\n"
            f"1. \"explanation\": a clear details summary explaining the issue\n"
            f"2. \"why_it_matters\": why this coding pattern is problematic\n"
            f"3. \"possible_impact\": what can go wrong if this is left in production\n"
            f"4. \"recommended_fix\": how the developer should repair this block\n"
            f"5. \"developer_friendly_summary\": a single-sentence friendly overview\n"
        )

        # 1. Try Gemini API first if key exists
        if self.gemini_api_key:
            try:
                gemini_url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"gemini-2.5-flash-preview-09-2025:generateContent?key={self.gemini_api_key}"
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
        # Note: In the future, this is where we would redirect call to local Qwen coder model
        # We can implement a probe/check or just try it if BUGHAWK_USE_LOCAL_BACKEND is configured
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
