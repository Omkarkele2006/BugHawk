# Architectural Blueprint

This document details the software architecture, component relationships, data flow, and limitations of the current BugHawk prototype.

---

## 1. System Overview

BugHawk is split into two independent services that reside in the same codebase but operate as separate runtimes in the current prototype:

1. **Flask Web Container (`Frontend/`):** Runs the user management, SQLite persistence layer, dashboard rendering, and handles AI chat prompts by calling external Gemini endpoints.
2. **FastAPI Model Container (`Backend/`):** Hosts a local Hugging Face transformer model for offline inference, intent classification, and reinforcement learning research.

Currently, **there is zero communication between the Frontend container and the Backend container**. The frontend acts as a high-fidelity visual mock for the scanner and uses external APIs for chat, while the backend hosts local ML models in isolation.

---

## 2. Component Directory Layout

```
c:/IMP/VIT/SY/SEM_1/EDI/EDI - BUGHAWK/
├── Frontend/                      # FLASK WEB APP (Port 5000)
│   ├── app.py                     # Main router, DB models, and controllers
│   ├── analyzer.py                # Mock scanner returning randomized metrics
│   ├── templates/                 # UI screens (Jinja2 templates)
│   ├── static/                    # Front-end asset dependencies (images, icons)
│   └── instance/                  # SQLite store directory
│
├── Backend/                       # FASTAPI MACHINE LEARNING APP (Port 8000)
│   ├── main.py                    # Endpoint listener (/submit)
│   ├── models/
│   │   ├── main_model.py          # Qwen-2.5 tokenizer & generation pipelines
│   │   ├── intent_classifier.py   # DistilBERT threat/debug classification model
│   │   └── model_cache.py         # 4-bit model quantizer and Singleton cache
│   ├── dataset/                   # Synthetic classification data generator script
│   └── prompt/                    # Instructions and rules for target LLMs
│
└── docs/                          # Architectural logs and Roadmap references
```

---

## 3. Database Schema

The database uses SQLite (handled via Flask-SQLAlchemy). The schema is structured as follows:

```mermaid
erDiagram
    USER ||--o{ ANALYSIS : "owns"
    USER {
        int id PK
        string github_id UNIQUE "GitHub account identifier for OAuth"
        string full_name "User real name"
        string email UNIQUE "User email (primary login)"
        string password_hash "Bcrypt salted hash"
        boolean is_verified "Has completed OTP check"
        string otp "6-digit OTP string"
        datetime otp_expiry "Expiration datetime (10 mins)"
        datetime date_created "User profile registration time"
        string username "User handle"
        string phone "Phone contact info"
        string timezone "Timezone setting (default UTC)"
        string experience_level "Experience level setting"
        string github_link "GitHub profile url"
        string linkedin_link "LinkedIn profile url"
        string portfolio_link "Portfolio website url"
        boolean two_factor_enabled "MFA status flag"
    }
    ANALYSIS {
        int id PK
        int user_id FK "User model owner link"
        string project_name "Target repository name"
        datetime timestamp "Datetime scan completed"
        string health_score_grade "A+ to F indicator"
        string health_score_status "Good or Needs Improvement"
        text issue_counts "Serialized JSON object tracking issue severities"
        text priority_issues "Serialized JSON list containing detailed issues"
        text bug_trend "Serialized JSON object representing Chart.js coordinates"
        text full_report_text "Long-form text log details"
    }
    CONTACT_MESSAGE {
        int id PK
        string name "Contact form submitter name"
        string email "Contact email"
        string subject "Message subject title"
        text message "Body text"
        datetime date_sent "Datetime sent"
    }
```

---

## 4. Current Request Flows

### A. Repository Analysis Flow
1. The user inputs a Git URL on the home screen and clicks **Analyze Now**.
2. Client-side JS triggers a POST request to the Flask server's `/analyze` route.
3. Flask calls `analyze_repository(repo_url)` in `Frontend/analyzer.py`.
4. The analyzer simulates processing (using `time.sleep(2)`) and constructs randomized grade metrics, issue counts, and mock issues.
5. Flask writes this analysis record to the SQLite database.
6. Flask returns a redirect URL to `/dashboard` containing the stringified analysis results in query parameters.
7. The browser loads the dashboard, parsing the URL arguments, and rendering the results using Chart.js graphs.

### B. AI Copilot Chat Flow
1. The developer types a message inside the chat console.
2. The UI sends a POST request with the prompt payload to Flask's `/api/chat` endpoint.
3. Flask checks if a `GEMINI_API_KEY` exists in `Frontend/.env`.
   * **If Present:** Flask sends an HTTP POST request to the Google Generative Language API (`https://generativelanguage.googleapis.com/...`), parses the resulting candidate text, and sends it back to the UI.
   * **If Missing:** Flask returns a fallback mock response asking the developer to configure their API key.

---

## 5. Architectural & Security Limitations

* **Service Disconnection:** The frontend web server runs independently of the local machine learning FastAPI backend. The local model (`Qwen2.5-Coder`) is never triggered by frontend requests.
* **Simulated Core Engine:** The repository analyzer is a complete mock, meaning no actual static or dynamic code scanning happens on git inputs.
* **Synchronous Requests:** The Flask analysis route is synchronous. Executing real code analysis synchronously inside web request-response loops will lead to network timeouts on large repositories.
* **Exposed Environment Secrets:** Sensitive keys (GitHub client IDs, SMTP Gmail passwords, Hugging Face read tokens, Gemini API keys) are checked in plaintext directly into the `.env` repository files.
* **Unprotected Machine Learning APIs:** The FastAPI endpoint `/submit` has no authentication tokens, request validation, or rate limiters, leaving it open to arbitrary model load exploitation.
* **Arbitrary Code Execution Risk:** The backend stubs for reinforcement learning verification (`eval_reward`) use raw Python `exec()` to run generated code on the host machine, introducing a severe remote code execution vulnerability.
