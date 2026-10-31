# Public HTTPS Mailroom Agent

Flask + Gemini + Neon PostgreSQL implementation of `ga5-mailroom-action-gate/v2`.

## Important behavior

- `POST /` supports `propose` and `commit`.
- `GET /health` checks database connectivity; `GET /` shows service metadata.
- Uses Gemini for uncached dossier decisions; cached decisions are reused by canonical dossier fingerprint.
- Persists evaluations, verifier keys, proposals, receipts, and terminal outcomes in PostgreSQL.
- Verifies all Ed25519 receipt signatures before storing any receipt.
- Does not connect to real email or case-management systems. `executed` means the grader's signed receipt accepted the proposed action; it records the terminal outcome and does not itself send email or mutate an external business system.
- External dossier content is sent to the configured model provider. Use only synthetic exam dossiers; never put real customer data or credentials into the prompt.

## Deploy to Render + Neon

1. Create a Neon PostgreSQL project and copy its pooled or direct connection string. Keep `sslmode=require`.
2. Create a Gemini API key in Google AI Studio.
3. Push this folder to a new GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "Build mailroom action gate"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/mailroom-agent.git
   git push -u origin main
   ```
4. In Render, choose **New + → Blueprint**, connect the repository, and deploy `render.yaml`.
5. Add `DATABASE_URL` and `GEMINI_API_KEY` in the Render environment settings. Do not commit `.env`.
6. After deployment, open `https://YOUR-SERVICE.onrender.com/health`; expect `{"database":"connected","status":"ok"}`.
7. Submit the root URL, such as `https://YOUR-SERVICE.onrender.com/`, without a query string or fragment.

## Local run (Windows PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env with Neon DATABASE_URL and GEMINI_API_KEY
$env:DATABASE_URL="your Neon connection string"
$env:GEMINI_API_KEY="your Gemini key"
python app.py
```

Then check `http://127.0.0.1:8080/health`.

## Before using a graded Check/Save

- Test the deployed `/health` endpoint.
- Confirm the Render logs show no database/model exceptions.
- The evaluator uses a fresh Ed25519 verifier key; the service stores the key supplied in each propose request.
- A `propose` request may take several model calls on the first run. Keep the Render instance warm if possible and avoid restarting during a check.
- A model decision that fails schema validation is rejected rather than replaced with a fabricated static answer.

## Notes

The service validates the outer request envelope and core dossier/line shape before model work. It validates exact frozen target/payload key sets and constants before caching a proposal. The action classifier is a baseline; hidden-case accuracy depends on model reasoning and evidence interpretation, so run a Check before using the final Save.
