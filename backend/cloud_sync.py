"""Future cloud propagation contract; local deployments remain cloud-free."""

from __future__ import annotations

from typing import Any, Protocol


class CloudSyncProvider(Protocol):
    def publish_intelligence(self, package: dict[str, Any]) -> dict[str, Any]:
        """Publish minimized intelligence, never raw message or attachment bytes."""


class LocalNoopCloudSync:
    def publish_intelligence(self, package: dict[str, Any]) -> dict[str, Any]:
        return {"status": "disabled", "published": False, "fields": sorted(package.keys())}


def build_intelligence_package(analysis: dict[str, Any]) -> dict[str, Any]:
    """Prepare the future contract using hashes and observable indicators only."""
    evidence = analysis.get("evidence") or {}
    indicators = analysis.get("indicators") or {}
    return {
        "schema_version": "1",
        "evidence_id": evidence.get("evidence_id"),
        "evidence_sha256": evidence.get("sha256"),
        "indicator_hashes": indicators,
        "campaign_fingerprint": (analysis.get("correlation") or {}).get("best_match_score"),
        "model_version": (analysis.get("ml_analysis") or {}).get("model_version"),
        "signed_evidence_reference": {"case_id": (analysis.get("investigation") or {}).get("case_id")},
        "contains_raw_email": False,
        "contains_attachment_bytes": False,
    }

