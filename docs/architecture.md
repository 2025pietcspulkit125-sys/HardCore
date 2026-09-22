# MailTrace AI Architecture

MailTrace AI is a local-first email forensics workflow:

`Next.js browser UI -> FastAPI API -> SQLite case store`

The browser never opens SQLite directly. `POST /api/analyze` parses an EML/MSG upload, calculates deterministic forensic findings, creates a unique `INV-...` case, stores structured metadata and analysis JSON, and returns the case context. Subsequent pages use the case ID in the URL and fetch the database-backed analysis.

The graph and correlation layers operate on observable evidence such as IPs, domains, URLs, relay hops, and attachment names. Shared observables are correlation signals, not proof of common actor ownership. Threat intelligence is enrichment, not attribution. DNS intelligence uses dnspython with bounded resolver timeouts for A, AAAA, MX, NS, and CNAME records.

The frontend uses a client-only Leaflet map for real provider coordinates and falls back to an evidence list when coordinates or map resources are unavailable. The Settings masking toggle controls presentation-layer masking through a shared browser preference; it never changes stored evidence.

AI Investigator uses an optional OpenAI-compatible provider when `OPENAI_API_KEY` is configured. Without it, the explainable deterministic investigator remains available.
