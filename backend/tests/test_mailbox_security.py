import asyncio
import base64
import os
import sys
import tempfile
import unittest

os.environ.setdefault("MAILTRACE_DB_PATH", tempfile.mktemp(suffix="-mailtrace-test.db"))
os.environ.setdefault("MAILBOX_INGESTION_ENABLED", "false")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import main
from mailbox_connectors import NormalizedEmailMessage
from mailbox_security import risk_policy


RAW = b"From: sender@example.com\nTo: user@example.com\nSubject: Team update\nMessage-ID: <test@example.com>\nAuthentication-Results: mx; spf=pass dkim=pass dmarc=pass\n\nHello team."


class MailboxSecurityTests(unittest.TestCase):
    def test_google_mail_relay_is_not_sender_origin(self):
        role = main._classify_ip_role(
            "209.85.220.41",
            {"asn": 15169, "organization": "Google LLC", "security": {}},
            {"hostname": "mail-oo1-f41.google.com", "aliases": []},
            observed_in_received=True,
        )
        self.assertEqual(role["role"], "MAIL_PROVIDER")
        self.assertFalse(role["is_sender_origin"])
        self.assertFalse(role["sender_geolocation_eligible"])

    def test_private_ip_never_gets_sender_geolocation(self):
        role = main._classify_ip_role("10.0.0.1", {}, {}, observed_in_received=True)
        self.assertEqual(role["role"], "UNKNOWN")
        self.assertFalse(role["sender_geolocation_eligible"])

    def test_public_ipv6_is_valid_but_not_assumed_sender(self):
        self.assertTrue(main._is_valid_ip("2001:4860:4860::8888"))
        role = main._classify_ip_role(
            "2001:4860:4860::8888",
            {"asn": 15169, "organization": "Google LLC", "security": {}},
            {"hostname": "dns.google", "aliases": []},
            observed_in_received=True,
        )
        self.assertEqual(role["role"], "MAIL_PROVIDER")
        self.assertFalse(role["is_sender_origin"])

    def test_x_originating_ip_is_untrusted_metadata(self):
        result = main._sender_source_assessment(
            {"headers": {"X-Originating-IP": "[203.0.113.55]"}},
            [],
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["untrusted_metadata_ips"], ["203.0.113.55"])

    def test_policy_is_conservative_by_default(self):
        result = risk_policy({"threat_detection": {"risk_score": 90, "risk_level": "CRITICAL"}})
        self.assertEqual(result["action"], "ALERT_REVIEW")
        self.assertFalse(result["automatic_quarantine_enabled"])

    def test_mailbox_analysis_is_deduplicated(self):
        message = NormalizedEmailMessage("mock", "same-provider-id", RAW, "2026-09-23T10:00:00Z")
        first = asyncio.run(main.analyze_mailbox_message(message))
        second = asyncio.run(main.analyze_mailbox_message(message))
        self.assertEqual(first["email"]["status"], "analyzed")
        self.assertEqual(second["email"]["status"], "duplicate")
        self.assertEqual(first["email"]["email_id"], second["email"]["email_id"])

    def test_attachment_hash_and_static_signature(self):
        from email import policy
        from email.parser import BytesParser
        parsed = BytesParser(policy=policy.default).parsebytes(b"From: a@example.com\nTo: b@example.com\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=report.pdf\n\nMZfake\n--x--\n")
        attachment = main.extract_attachments(parsed)[0]
        self.assertEqual(len(attachment["sha256"]), 64)
        self.assertEqual(attachment["magic"], "pe-executable")
        self.assertIn("executable-or-script-indicator", attachment["malware_indicators"])

    def test_all_ml_labels_load(self):
        labels = {main.classify_with_local_ml("", "", "", [], [""])["ml_classification"]}
        artifact_labels = set(main.classify_with_local_ml("", "", "", [], []).get("ml_probabilities", {}).keys())
        self.assertEqual(artifact_labels, {"LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION", "BEC_FRAUD", "MALWARE"})
        self.assertTrue(labels)


if __name__ == "__main__":
    unittest.main()
