# BugHawk - AI-Powered Code Analysis & Copilot Suite

BugHawk is an intelligent application designed to streamline the Software Development Life Cycle (SDLC) by providing interactive AI-assisted code reviews, security vulnerability checks, performance bottleneck audits, and automated docstrings generation.

> [!IMPORTANT]
> **Prototype Phase Notice:** 
> BugHawk is currently in a prototype phase. The interactive AI Copilot chat leverages the external Gemini API, while the repository scan metrics in the dashboard are currently simulated using high-fidelity mock data. The local Machine Learning server (in `Backend/`) runs separately and is not yet integrated into the runtime request pipeline of the web frontend.

---

## Project Structure

The project is structured into two main service containers:

* **[Frontend/](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/Frontend/)**: The user-facing Flask web application. It handles local user authentication, GitHub OAuth, SMTP-based email OTP verification, the dashboard statistics, scan history databases, and the chat copilot UI.
* **[Backend/](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/Backend/)**: The FastAPI-powered machine learning inference API. It hosts the coder model (`Qwen2.5-Coder-1.5B-Instruct`), manages model weights caching, runs DistilBERT sequence classifications, and stubs reinforcement learning feedback mechanisms.
* **[docs/](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/docs/)**: Engineering logs and architecture references detailing layouts and roadmap plans.
* **`instance/`**: Directory containing local SQLite state databases.

---

## Local Development Setup

To run the application locally, you will need to start both the Frontend web container and the Backend ML container.

### Prerequisites
* Python 3.11 or higher
* `uv` (recommended for faster package resolutions in the Backend)

### 1. Launch the Backend (FastAPI ML Service)
Navigate to the `Backend/` folder, configure dependencies, and start the ASGI web service on port `8000`:
```bash
cd Backend
pip install uv
uv run fastapi dev main.py
```
*The FastAPI application will load `Qwen2.5-Coder-1.5B-Instruct` (downloading weights from Hugging Face if not cached) and expose a `/submit` endpoint.*

### 2. Launch the Frontend (Flask Web Application)
Navigate to the `Frontend/` folder, configure a virtual environment, install dependencies, and run the developer server on port `5000`:
```bash
cd Frontend
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```
*Access the application by navigating your web browser to `http://localhost:5000`.*

---

## Environment Variables
The applications look for variables stored in `.env` files inside their respective directories:
* **Frontend (`Frontend/.env`):**
  * `GEMINI_API_KEY`: API key used to process requests inside the AI Copilot.
  * `SECRET_KEY`: Flask session security signature.
  * `MAIL_USERNAME` / `MAIL_PASSWORD`: Google SMTP sender setup for OTP codes.
  * `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`: OAuth integration application keys.
* **Backend (`Backend/.env`):**
  * `token_hf`: Hugging Face read access token.

---

## Roadmap & Architecture
For deep architectural details, decisions log, and future steps for backend integration, please check the engineering documentation:
* [Architecture Blueprint](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/docs/ARCHITECTURE.md)
* [Modernization Roadmap](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/docs/ROADMAP.md)
* [Architecture Decisions Log](file:///c:/IMP/VIT/SY/SEM_1/EDI/EDI%20-%20BUGHAWK/docs/DECISIONS.md)

---
*Developed by Group SY-F-18.*
