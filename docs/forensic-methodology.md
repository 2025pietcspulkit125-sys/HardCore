# Forensic Methodology

MailTrace preserves the uploaded file hash and stores structured findings without storing raw email bytes. Header parsing reconstructs observed Received hops and identifies the earliest visible public infrastructure indicator when available.

Risk classification combines authentication, sender relationship, content, URL, attachment, impersonation, and correlation signals. The score is an explainable deterministic assessment, not a claim of malicious intent by itself.

A bundled local multinomial text classifier provides an additional ML triage signal from subject, body, sender, URLs, and attachment names. Its synthetic training set is for demonstration and does not represent real-world prevalence. The deterministic forensic engine remains authoritative for explainability and is never replaced by the ML label.

IP geolocation describes network or hosting infrastructure. It does not prove the sender's physical location or identity. DNS/RDAP values are reported only when available; unavailable fields are not inferred. Cross-case relationships use shared observable indicators and are not proof that the same actor created the cases. External threat intelligence is enrichment, not proof. Local alerts and audit events provide operational and chain-of-custody support, not attribution.
