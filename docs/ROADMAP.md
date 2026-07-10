# Modernization Roadmap

This document outlines the phased plan to transition the BugHawk prototype into a production-ready, secure, and integrated codebase.

---

## Phase 1: Critical Security & Core Integration (Short-Term)

### 1. Secrets Management and Environmental Security
* **Objective:** Secure credentials and tokens.
* **Tasks:**
  * Purge the existing git history to remove checked-in `.env` files.
  * Inject environmental keys at runtime using container orchestration or key management systems.
  * Define strict rules preventing the check-in of configuration state files.

### 2. Connect Frontend to the local ML Backend
* **Objective:** Enable local model processing.
* **Tasks:**
  * Update Flask's `/api/chat` route to query the FastAPI backend running on port `8000` (instead of using external Gemini APIs directly or returning mock data).
  * Configure FastAPI's `/submit` endpoint to accept queries from the Flask container IP only, removing the global CORS wildcard (`*`).
  * Implement basic API Token verification headers between the two containers.

### 3. Remove Raw `exec()` Code Execution
* **Objective:** Prevent arbitrary remote code execution on the server host.
* **Tasks:**
  * Disable raw `exec()` commands in reward model loops.
  * Design a sandboxed micro-container execution environment (e.g., Docker containers with resource constraints) to run and test model-generated code safely.

---

## Phase 2: Asynchronous Workflows & Real Scanners (Medium-Term)

### 1. Integrate Real Repository Scanners
* **Objective:** Replace mock statistics with functional code reviews.
* **Tasks:**
  * Implement cloning operations when a user inputs a repository URL.
  * Execute local static analysis utilities (e.g., `Bandit` for security vulnerabilities, `Pylint` or `Flake8` for bugs, `Radon` for cyclomatic complexity metrics).
  * Pass flagged diagnostics and issues to the local Qwen LLM backend to request patch proposals.

### 2. Implement Asynchronous Task Execution (Celery + Redis)
* **Objective:** Prevent timeouts during repository clones and audits.
* **Tasks:**
  * Integrate Celery task runners alongside a Redis message broker.
  * Offload repository clones and analysis pipelines from the web thread to background task workers.
  * Configure polling or WebSockets to update the frontend dashboard progress bars dynamically.

### 3. Database & Layer Migrations
* **Objective:** Move to a multi-client production database.
* **Tasks:**
  * Replace the local file-based SQLite database with a production-grade PostgreSQL service.
  * Extract inline Javascript code blocks and CSS styles from Jinja2 templates into individual static assets.

---

## Phase 3: Developer Ecosystem & Scaling (Long-Term)

### 1. CI/CD Pre-Commit and PR Integrations
* **Objective:** Automate audits at the pull request level.
* **Tasks:**
  * Establish pre-commit configurations that trigger repository scans automatically before developer commits.
  * Create a GitHub Action runner that submits code diffs to BugHawk during Pull Requests, writing comments on code changes.

### 2. High-Performance Inference Configurations
* **Objective:** Support high concurrent chat volumes.
* **Tasks:**
  * Replace default Hugging Face Transformers inference with high-performance inference engines like vLLM.
  * Configure model scaling and request queuing to leverage multiple GPU instances.
