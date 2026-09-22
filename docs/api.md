# MailTrace AI API

Base URL: `http://127.0.0.1:8000`

- `GET /health` - backend health.
- `POST /api/analyze` - multipart upload with `file` (`.eml`; `.msg` where parser support exists).
- `GET /api/database/status` - SQLite status and case count.
- `GET /api/dashboard/summary` - database-backed KPIs, risk distribution, activity, and recent cases.
- `GET /api/alerts` - persisted local alerts, optionally filtered with `unacknowledged_only=true`.
- `POST /api/alerts/{alert_id}/acknowledge` - acknowledge one local alert.
- `GET /api/investigations` - persistent case list.
- `GET /api/investigations/{case_id}/analysis` - stored structured analysis.
- `GET /api/investigations/{case_id}/audit` - chain-of-custody events for a case.
- `GET /api/correlation/{case_id}` - related cases and shared observable indicators.
- `GET /api/threat-graph/{case_id}` - selected-case evidence graph.
- `POST /api/threat-intelligence` - optional IP/domain/URL enrichment.
- `GET /api/threat-intelligence/status` - provider availability/configuration.
- `GET /api/ai-investigator/status` - AI provider mode.
- `POST /api/ai-investigator` - case-aware question and answer.
- `GET /api/ai-investigator/{case_id}/history` - persisted conversation.
- `DELETE /api/ai-investigator/{case_id}/history` - clear one case's conversation.
- `GET /api/reports/{case_id}` - structured forensic report.
- `GET /api/reports/{case_id}/pdf` - printable PDF when ReportLab is installed.
