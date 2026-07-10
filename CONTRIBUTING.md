# Contributing to BugHawk

Thank you for your interest in contributing to BugHawk! To keep the repository clean, secure, and professional, please adhere to the following guidelines.

## Development Environment Setup

BugHawk consists of two separate Python applications that run independently in the current prototype:
1. **Frontend (Flask Web App):** Managed via Python. Requires environment keys for external integrations (Gemini API, GitHub OAuth, SMTP Mail).
2. **Backend (FastAPI Model App):** Managed via Python (ideally using `uv`). Loads causal coding models (`Qwen2.5-Coder`).

### 1. Setting Up the Frontend
```bash
cd Frontend
# Create virtual environment
python -m venv venv
# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
# Install dependencies
pip install -r requirements.txt # (Check pyproject.toml or setup.cfg if updated)
# Run application
python app.py
```

### 2. Setting Up the Backend
```bash
cd Backend
# Install uv if not already installed (recommended)
pip install uv
# Resolve and run the dev server
uv run fastapi dev main.py
```

---

## Coding Standards

* **Style Conventions:** We use `.editorconfig` to enforce formatting. Indentation is set to **4 spaces** for Python and **2 spaces** for HTML, CSS, and JS.
* **Formatters & Linters:** We use `black` for formatting and `flake8` for linting.
* **Pre-commit Hooks:** Please install pre-commit hooks locally to validate formatting before commiting:
  ```bash
  pip install pre-commit
  pre-commit install
  ```

---

## Important Rules

1. **Security & Secrets:** **NEVER** commit plain-text API keys, passwords, or Hugging Face tokens to version control. Ensure all secrets are placed in local `.env` files which are ignored by git.
2. **Decoupled Architecture:** Keep the frontend logic in the `Frontend/` folder and machine learning logic in `Backend/`. Do not introduce dependencies between the two folders that run at import time.
3. **No Raw Code Execution on Host:** Any verification routines or reward model loops executing generated code must be securely sandboxed. Do not execute model outputs directly on your local system using `exec()`.
