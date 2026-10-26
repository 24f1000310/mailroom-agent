# Public HTTPS Mailroom Agent

FastAPI + Gemini + PostgreSQL implementation scaffold for `ga5-mailroom-action-gate/v2`.

## Local setup
1. Python 3.11+
2. `python -m venv .venv`
3. Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
4. `pip install -r requirements.txt`
5. Copy `.env.example` to `.env`; fill Gemini API key and PostgreSQL URL.
6. `uvicorn main:app --reload --port 8000`
7. Health: `http://127.0.0.1:8000/health`

## Deploy
Push to GitHub. In Render create a Web Service from the repo (or use render.yaml), set `GEMINI_API_KEY` and `DATABASE_URL`, and deploy. Submit the HTTPS root URL, e.g. `https://your-service.onrender.com/`.

## Important
This is a starting implementation, not a guarantee of passing the hidden grader. Run local contract tests and inspect logs. It currently focuses on envelope validation, canonical digests, persistence, action schema validation, receipt signature verification, and replay handling. Before submission, test all action-specific schemas and exact replay against the grader's public examples.
