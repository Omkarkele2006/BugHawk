import random
import time
from datetime import datetime, timezone

def analyze_repository(repo_url):
    """
    MOCK ANALYSIS FUNCTION
    - Takes a repository URL as input.
    - Simulates a code analysis process.
    - Returns a dictionary with the analysis results.
    
    --> Replace this function with your teammate's actual model.
        Just ensure the return format (the dictionary keys) remains the same.
    """
    print(f"Analyzing repository: {repo_url}...")
    time.sleep(2) 
    
    try:
        project_name = repo_url.split('/')[-1].replace('.git', '')
    except:
        project_name = "Unknown Project"

    # Generate realistic, randomized mock data
    security_issues = random.randint(5, 25)
    bugs = random.randint(10, 50)
    performance_issues = random.randint(0, 15)
    code_smells = random.randint(20, 100)
    
    total_issues = security_issues + bugs + performance_issues + code_smells
    
    score_value = 100 - (security_issues * 2 + bugs * 1 + performance_issues * 0.5 + code_smells * 0.2)
    grade = "F"
    if score_value > 90: grade = "A+"
    elif score_value > 80: grade = "A"
    elif score_value > 70: grade = "B+"
    elif score_value > 60: grade = "B"
    elif score_value > 50: grade = "C"

    bug_trend_data = {
        'critical': [random.randint(2, 5) for _ in range(5)],
        'major': [random.randint(8, 15) for _ in range(5)]
    }

    high_priority_issues = [
        {
            "title": "Potential SQL Injection Vulnerability",
            "file": f"src/controllers/user_controller.py",
            "line": random.randint(50, 150),
            "severity": "CRITICAL"
        },
        {
            "title": "Inefficient Database Query (N+1 Problem)",
            "file": f"api/queries.js",
            "line": random.randint(80, 200),
            "severity": "MAJOR"
        },
        {
            "title": "Cross-Site Scripting (XSS) Risk",
            "file": f"views/profile.ejs",
            "line": random.randint(20, 60),
            "severity": "CRITICAL"
        }
    ]

    results = {
        "projectName": project_name,
        # NEW: Added a real timestamp
        "lastScanned": datetime.now(timezone.utc).isoformat(),
        "healthScore": {
            "grade": grade,
            "status": "Good" if score_value > 65 else "Needs Improvement"
        },
        "issueCounts": {
            "security": security_issues,
            "bugs": bugs,
            "performance": performance_issues,
            "codeSmells": code_smells
        },
        "bugTrend": bug_trend_data,
        "priorityIssues": random.sample(high_priority_issues, 2)
    }
    
    print("Analysis complete.")
    return results