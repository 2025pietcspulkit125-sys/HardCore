"""SQLite mailbox state, evidence indexing, policy decisions, and live events."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


EVENTS = ("EMAIL_RECEIVED", "EMAIL_ANALYSIS_STARTED", "EMAIL_ANALYSIS_COMPLETED", "RISK_UPDATED", "THREAT_DETECTED", "EMAIL_QUARANTINED", "CASE_CREATED", "INDICATOR_EXTRACTED", "MODEL_UPDATED")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_mailbox_store(connection: sqlite3.Connection) -> None:
    statements = [
        """CREATE TABLE IF NOT EXISTS mailbox_accounts (account_id TEXT PRIMARY KEY, provider TEXT NOT NULL, address TEXT, status TEXT NOT NULL, permissions_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS mailbox_sync_state (account_id TEXT PRIMARY KEY, state TEXT NOT NULL, cursor TEXT, last_sync_at TEXT, next_retry_at TEXT, error TEXT, FOREIGN KEY(account_id) REFERENCES mailbox_accounts(account_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_messages (email_id TEXT PRIMARY KEY, account_id TEXT, provider TEXT NOT NULL, provider_message_id TEXT NOT NULL, content_sha256 TEXT NOT NULL, message_id TEXT, case_id TEXT, received_at TEXT NOT NULL, processed_at TEXT, status TEXT NOT NULL, UNIQUE(provider, provider_message_id), UNIQUE(provider, content_sha256))""",
        """CREATE TABLE IF NOT EXISTS email_evidence (evidence_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, sha256 TEXT NOT NULL, captured_at TEXT NOT NULL, chain_of_custody_json TEXT NOT NULL, FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_attachments (attachment_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, filename TEXT, mime_type TEXT, size INTEGER, sha256 TEXT, verdict TEXT, findings_json TEXT NOT NULL DEFAULT '[]', FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_urls (url_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, url TEXT NOT NULL, domain TEXT, verdict TEXT, findings_json TEXT NOT NULL DEFAULT '[]', FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_ips (ip_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, ip TEXT NOT NULL, source TEXT, FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_risk_scores (email_id TEXT PRIMARY KEY, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, classification TEXT NOT NULL, confidence TEXT, features_json TEXT NOT NULL, model_version TEXT, created_at TEXT NOT NULL, FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_model_predictions (prediction_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, model_version TEXT NOT NULL, label TEXT NOT NULL, confidence REAL NOT NULL, features_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_actions (action_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, reason_json TEXT NOT NULL, provider_response_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, UNIQUE(email_id, action), FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS email_alerts (alert_id TEXT PRIMARY KEY, email_id TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(email_id) REFERENCES email_messages(email_id) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS mailbox_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, email_id TEXT, case_id TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS model_versions (model_version TEXT PRIMARY KEY, dataset_version TEXT, artifact_path TEXT, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS training_runs (run_id TEXT PRIMARY KEY, model_version TEXT NOT NULL, dataset_version TEXT NOT NULL, status TEXT NOT NULL, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL)""",
    ]
    for statement in statements:
        connection.execute(statement)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_email_messages_received ON email_messages(received_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_events_created ON mailbox_events(created_at)")


def record_event(connection: sqlite3.Connection, event_type: str, payload: dict[str, Any], *, email_id: str | None = None, case_id: str | None = None) -> dict[str, Any]:
    event = {"event_id": f"MEV-{uuid4().hex[:16].upper()}", "event_type": event_type, "email_id": email_id, "case_id": case_id, "payload": payload, "created_at": now()}
    connection.execute("INSERT INTO mailbox_events(event_id,event_type,email_id,case_id,payload_json,created_at) VALUES(?,?,?,?,?,?)", (event["event_id"], event_type, email_id, case_id, json.dumps(payload, ensure_ascii=False), event["created_at"]))
    return event


def risk_policy(analysis: dict[str, Any]) -> dict[str, Any]:
    score = int((analysis.get("threat_detection") or {}).get("risk_score") or 0)
    level = str((analysis.get("threat_detection") or {}).get("risk_level") or "LOW").upper()
    enabled = os.getenv("AUTO_QUARANTINE_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
    high = int(os.getenv("HIGH_RISK_THRESHOLD", "50"))
    critical = int(os.getenv("CRITICAL_RISK_THRESHOLD", "75"))
    action = "STORE"
    if enabled and (score >= critical or level == "CRITICAL"):
        action = "QUARANTINE"
    elif enabled and (score >= high or level == "HIGH"):
        action = "QUARANTINE"
    elif level == "MEDIUM" or score >= 30:
        action = "ALERT_REVIEW"
    return {"action": action, "score": score, "risk_level": level, "automatic_quarantine_enabled": enabled, "thresholds": {"high": high, "critical": critical}, "reason": "Policy decision uses deterministic risk level, configured thresholds, and AUTO_QUARANTINE_ENABLED; mail is never permanently deleted."}


def record_mailbox_analysis(connection: sqlite3.Connection, message: Any, analysis: dict[str, Any], account_id: str | None = None) -> dict[str, Any]:
    content_hash = hashlib.sha256(message.raw_bytes).hexdigest()
    evidence = analysis.get("evidence") or {}
    email_id = f"MAIL-{uuid4().hex[:16].upper()}"
    existing = connection.execute("SELECT email_id, case_id, status FROM email_messages WHERE provider=? AND (provider_message_id=? OR content_sha256=?)", (message.provider, message.provider_message_id, content_hash)).fetchone()
    if existing:
        return {"email_id": existing[0], "case_id": existing[1], "status": "duplicate", "action": "NOOP"}
    case_id = (analysis.get("investigation") or {}).get("case_id")
    connection.execute("INSERT INTO email_messages(email_id,account_id,provider,provider_message_id,content_sha256,message_id,case_id,received_at,processed_at,status) VALUES(?,?,?,?,?,?,?,?,?,?)", (email_id, account_id, message.provider, message.provider_message_id, content_hash, (analysis.get("email") or {}).get("message_id"), case_id, message.received_at, now(), "ANALYZED"))
    connection.execute("INSERT INTO email_evidence(evidence_id,email_id,sha256,captured_at,chain_of_custody_json) VALUES(?,?,?,?,?)", (evidence.get("evidence_id") or f"MT-{content_hash[:12].upper()}", email_id, evidence.get("sha256") or content_hash, evidence.get("captured_at") or now(), json.dumps({"source": "mailbox", "provider": message.provider, "provider_message_id": message.provider_message_id, "captured_at": now()})))
    for item in analysis.get("attachments", []):
        if isinstance(item, dict):
            connection.execute("INSERT INTO email_attachments(attachment_id,email_id,filename,mime_type,size,sha256,verdict,findings_json) VALUES(?,?,?,?,?,?,?,?)", (f"ATT-{uuid4().hex[:12].upper()}", email_id, item.get("filename"), item.get("content_type"), int(item.get("size") or 0), item.get("sha256"), "HIGH" if item.get("malware_indicators") else "REVIEW", json.dumps(item.get("malware_indicators") or [])))
    for item in analysis.get("url_analysis", []):
        if isinstance(item, dict):
            url = item.get("url") or item.get("indicator")
            if url:
                connection.execute("INSERT INTO email_urls(url_id,email_id,url,domain,verdict,findings_json) VALUES(?,?,?,?,?,?)", (f"URL-{uuid4().hex[:12].upper()}", email_id, url, item.get("domain"), "HIGH" if any(str(x.get("severity")).lower() == "high" for x in item.get("findings", []) if isinstance(x, dict)) else "REVIEW", json.dumps(item.get("findings") or [])))
    for ip in (analysis.get("indicators") or {}).get("ips", []):
        connection.execute("INSERT INTO email_ips(ip_id,email_id,ip,source) VALUES(?,?,?,?)", (f"IP-{uuid4().hex[:12].upper()}", email_id, ip, "headers-or-body"))
    detection = analysis.get("threat_detection") or {}
    ml = analysis.get("ml_analysis") or {}
    model_version = str(ml.get("model_version") or ml.get("ml_model") or "unknown")
    connection.execute("INSERT INTO email_risk_scores(email_id,risk_score,risk_level,classification,confidence,features_json,model_version,created_at) VALUES(?,?,?,?,?,?,?,?)", (email_id, int(detection.get("risk_score") or 0), str(detection.get("risk_level") or "LOW"), str(detection.get("classification") or "UNKNOWN"), str(detection.get("confidence") or "LOW"), json.dumps(detection.get("components") or {}), model_version, now()))
    if ml.get("ml_classification"):
        connection.execute("INSERT INTO email_model_predictions(prediction_id,email_id,model_version,label,confidence,features_json,created_at) VALUES(?,?,?,?,?,?,?)", (f"PRED-{uuid4().hex[:12].upper()}", email_id, model_version, ml.get("ml_classification"), float(ml.get("ml_confidence") or 0), json.dumps(ml.get("ml_features_used") or []), now()))
    event = record_event(connection, "EMAIL_ANALYSIS_COMPLETED", {"risk_score": detection.get("risk_score"), "risk_level": detection.get("risk_level"), "classification": detection.get("classification")}, email_id=email_id, case_id=case_id)
    connection.commit()
    return {"email_id": email_id, "case_id": case_id, "status": "analyzed", "content_sha256": content_hash, "policy": risk_policy(analysis), "event": event}

