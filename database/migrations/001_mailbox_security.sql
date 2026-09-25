-- SQLite-compatible mailbox security schema. The application applies this
-- migration idempotently at startup; PostgreSQL types can use JSONB instead of
-- the *_json TEXT columns during a future deployment migration.
CREATE TABLE IF NOT EXISTS mailbox_accounts (account_id TEXT PRIMARY KEY, provider TEXT NOT NULL, address TEXT, status TEXT NOT NULL, permissions_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mailbox_sync_state (account_id TEXT PRIMARY KEY, state TEXT NOT NULL, cursor TEXT, last_sync_at TEXT, next_retry_at TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS email_messages (email_id TEXT PRIMARY KEY, account_id TEXT, provider TEXT NOT NULL, provider_message_id TEXT NOT NULL, content_sha256 TEXT NOT NULL, message_id TEXT, case_id TEXT, received_at TEXT NOT NULL, processed_at TEXT, status TEXT NOT NULL, UNIQUE(provider, provider_message_id), UNIQUE(provider, content_sha256));
CREATE TABLE IF NOT EXISTS email_evidence (evidence_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, sha256 TEXT NOT NULL, captured_at TEXT NOT NULL, chain_of_custody_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS email_attachments (attachment_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, filename TEXT, mime_type TEXT, size INTEGER, sha256 TEXT, verdict TEXT, findings_json TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS email_urls (url_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, url TEXT NOT NULL, domain TEXT, verdict TEXT, findings_json TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS email_ips (ip_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, ip TEXT NOT NULL, source TEXT);
CREATE TABLE IF NOT EXISTS email_risk_scores (email_id TEXT PRIMARY KEY, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, classification TEXT NOT NULL, confidence TEXT, features_json TEXT NOT NULL, model_version TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS email_model_predictions (prediction_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, model_version TEXT NOT NULL, label TEXT NOT NULL, confidence REAL NOT NULL, features_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS email_actions (action_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, reason_json TEXT NOT NULL, provider_response_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, UNIQUE(email_id, action));
CREATE TABLE IF NOT EXISTS email_alerts (alert_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mailbox_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, email_id TEXT, case_id TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS model_versions (model_version TEXT PRIMARY KEY, dataset_version TEXT, artifact_path TEXT, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS training_runs (run_id TEXT PRIMARY KEY, model_version TEXT NOT NULL, dataset_version TEXT NOT NULL, status TEXT NOT NULL, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL);
