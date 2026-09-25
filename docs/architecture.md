# MailTrace AI Architecture

MailTrace AI is a local-first email forensics workflow:

`Next.js browser UI -> FastAPI API -> SQLite case store`

The browser never opens SQLite directly. `POST /api/analyze` parses an EML/MSG upload, calculates deterministic forensic findings, creates a unique `INV-...` case, stores structured metadata and analysis JSON, and returns the case context. Subsequent pages use the case ID in the URL and fetch the database-backed analysis.

## Real-time mailbox path

```text
Gmail OAuth / Microsoft Graph OAuth / IMAP
        -> IngestionManager (polling fallback, backoff, dedupe)
        -> normalized RFC822 message + SHA-256 evidence capture
        -> existing forensic analyzer (headers, auth, URLs, attachments, ML)
        -> SQLite mailbox tables + case/evidence/audit records
        -> policy engine (store, alert/review, quarantine)
        -> SSE feed and mailbox dashboard
```

Provider adapters never expose credentials to the frontend. Gmail and Graph
support provider API polling and safe move/label operations when a server-side
access token is configured; IMAP is a least-privilege fallback. Automatic
quarantine is disabled by default and is a reversible provider move/label, never
a permanent delete. A future `CloudSyncProvider` can consume minimized indicator
packages, model versions, campaign fingerprints, and signed evidence references;
raw messages and attachments are not broadcast by default.

The mailbox schema is applied by `backend/mailbox_security.py` and documented in
`database/migrations/001_mailbox_security.sql`. `GET /api/mailbox/feed` provides
SSE for live updates; polling of `/api/mailbox/messages` remains the fallback.

The graph and correlation layers operate on observable evidence such as IPs, domains, URLs, relay hops, and attachment names. Shared observables are correlation signals, not proof of common actor ownership. Threat intelligence is enrichment, not attribution. DNS intelligence uses dnspython with bounded resolver timeouts for A, AAAA, MX, NS, and CNAME records.

The frontend uses a client-only Leaflet map for real provider coordinates and falls back to an evidence list when coordinates or map resources are unavailable. The Settings masking toggle controls presentation-layer masking through a shared browser preference; it never changes stored evidence.

AI Investigator uses an optional OpenAI-compatible provider when `OPENAI_API_KEY` is configured. Without it, the explainable deterministic investigator remains available.
