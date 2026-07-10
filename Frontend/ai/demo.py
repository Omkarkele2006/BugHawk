import sys
import os

# Append the frontend folder path to PYTHONPATH to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.base import Finding
from ai.explainer import BHAIFindingExplainer

def run_demo():
    print("=== BUGHAWK AI EXPLAINER MODULE DEMONSTRATION ===")
    
    # 1. Create a dummy normalized Finding representing a SQL injection vulnerability
    sql_finding = Finding(
        scanner="bandit",
        category="security",
        severity="CRITICAL",
        file="src/controllers/auth_controller.py",
        line=42,
        rule_id="B608",
        title="Possible SQL injection vector via string concatenation",
        description="Found sql query assembly: 'SELECT * FROM users WHERE user_id = ' + user_input",
        recommendation="Verify inputs are parameterized using ORM bindings or cursor statement params.",
        confidence="HIGH"
    )

    # 2. Create a dummy complexity Finding representing a radon complexity ranking smell
    radon_finding = Finding(
        scanner="radon",
        category="codeSmells",
        severity="MAJOR",
        file="src/utils/calculator.py",
        line=104,
        rule_id="RADON-C",
        title="High cyclomatic complexity inside calculate_matrix function",
        description="Complexity score is 15 (Rank C). Too many nested loops and conditional branches.",
        recommendation="Decompose logic statement blocks into small helper functions.",
        confidence="HIGH"
    )

    # 3. Instantiate explainer
    explainer = BHAIFindingExplainer()

    print("\n--- 1. Testing Single Security Finding ---")
    print(f"Finding Rule ID: {sql_finding.rule_id} | Title: {sql_finding.title}")
    
    # Process single finding
    explanation1 = explainer.explain_finding(sql_finding)
    
    print(f"Explanation: {explanation1.explanation}")
    print(f"Why It Matters: {explanation1.why_it_matters}")
    print(f"Possible Impact: {explanation1.possible_impact}")
    print(f"Recommended Fix: {explanation1.recommended_fix}")
    print(f"Developer Friendly Summary: {explanation1.developer_friendly_summary}")

    print("\n--- 2. Testing Batch Findings Mapping ---")
    findings_list = [sql_finding, radon_finding]
    
    # Process multiple findings
    explanations_map = explainer.explain_findings(findings_list)
    
    for key, explanation in explanations_map.items():
        print(f"\n[Key: {key}]")
        print(f"-> Summary: {explanation.developer_friendly_summary}")
        print(f"-> Recommended Fix: {explanation.recommended_fix}")

if __name__ == "__main__":
    run_demo()
