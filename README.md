# MailTrace AI

MailTrace AI is an AI-powered email threat detection, geolocation, and forensic intelligence platform for SIH PS26106. It turns suspicious email into a structured investigation with evidence hashing, authentication analysis, IOC extraction, relay reconstruction, a bundled offline ML triage layer, persistent cases, local high-risk alerts, chain-of-custody events, cross-case correlation, threat graphing, optional DNS/intelligence enrichment, AI Investigator Q&A, and forensic reports.

## Architecture

`Next.js + TypeScript -> FastAPI -> SQLite`

The backend database is the source of truth. The frontend never accesses SQLite directly. Each analysis creates a unique `INV-...` case and stores structured metadata and analysis JSON, but not raw email bytes.

## Start locally

Backend:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m uvicorn main:app --reload
```

Frontend:

```powershell
cd frontend
npm install
npm run build
npm start
```

Open `http://localhost:3000`.

## Configuration

Copy `.env.example` values into the backend environment when needed:

- `MAILTRACE_DB_PATH` optionally changes the SQLite path.
- `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` enable optional reputation enrichment.
- `OPENAI_API_KEY` and `OPENAI_MODEL` enable the optional evidence-grounded AI provider. Without a key, deterministic AI Investigator fallback remains active.

The local ML classifier uses separated synthetic training data in `backend/ml_data/`, a generated model artifact, and transparent token likelihoods. Retrain it with `backend/venv/Scripts/python.exe backend/train_ml_model.py` to print accuracy, precision, recall, and F1 metrics. It is a locally trained lightweight classifier suitable for prototype/SIH demonstration, does not represent real-world threat prevalence, and never replaces the deterministic forensic engine. `MAILTRACE_ALERT_THRESHOLD` optionally controls the local alert threshold and defaults to `80`.

## Main workflow

Upload EML/MSG -> parse headers/body/attachments -> analyze authentication, content, URLs, attachments, and sender relationships -> extract observable indicators -> calculate risk -> persist a case -> correlate with historical cases -> inspect graph/intelligence -> ask AI Investigator -> generate report.

High-risk cases also create durable local alerts. Analysis and report access create custody events in SQLite. DNS intelligence performs A, AAAA, MX, NS, and CNAME lookups through the configured resolver and gracefully degrades when unavailable. Threat Intelligence includes an interactive infrastructure geolocation map with a list fallback. IP coordinates represent observed infrastructure location only.

## API overview

See [docs/api.md](docs/api.md). Architecture and forensic safety notes are in [docs/architecture.md](docs/architecture.md) and [docs/forensic-methodology.md](docs/forensic-methodology.md). The click-through demo is in [docs/demo-guide.md](docs/demo-guide.md).

## Forensic safety

IP results describe observed infrastructure or provider location, not sender physical location or identity. Correlation uses shared observable indicators and is not proof of a common actor. Threat intelligence is enrichment, not proof. The application preserves these cautions in analysis, graph, AI, and report views.

## Handling notes

Sensitive-data masking is configurable from Settings and applies only to presentation; case IDs, evidence IDs, and SHA-256 values remain visible. MSG parsing depends on the existing parser support in the local environment. External provider results require network access and configured keys. PDF export requires ReportLab; browser print and JSON export remain available without it. The bundled ML model is a demonstration classifier, not a production-trained threat model.
