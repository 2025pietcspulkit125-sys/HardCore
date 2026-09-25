"""Optional structured local LLM explanation layer with a safe deterministic fallback."""

from __future__ import annotations

import json
import os
import argparse
import sys
import urllib.request
from typing import Any


def minimized_evidence(analysis: dict[str, Any]) -> dict[str, Any]:
    detection = analysis.get("threat_detection") or {}
    return {
        "case_id": (analysis.get("investigation") or {}).get("case_id"),
        "evidence_id": (analysis.get("evidence") or {}).get("evidence_id"),
        "classification": detection.get("classification"),
        "risk_score": detection.get("risk_score"),
        "risk_level": detection.get("risk_level"),
        "components": detection.get("components", {}),
        "authentication": analysis.get("authentication", {}),
        "sender_analysis": analysis.get("sender_analysis", {}),
        "attachment_analysis": analysis.get("attachment_analysis", {}),
        "url_findings": [item.get("findings", []) for item in analysis.get("url_analysis", []) if isinstance(item, dict)],
        "evidence": analysis.get("evidence", []),
    }


def _fallback(evidence: dict[str, Any]) -> dict[str, Any]:
    score = int(evidence.get("risk_score") or 0)
    level = str(evidence.get("risk_level") or "LOW")
    components = evidence.get("components") or {}
    reasons = []
    citations = []
    for key, component in components.items():
        if not isinstance(component, dict) or not component.get("score"):
            continue
        reasons.append(f"{key.replace('_', ' ').title()} contributed {component.get('score')}/{component.get('max_score')} points.")
        citations.extend(item.get("id") for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("type", "").lower() in key.lower())
    return {
        "provider": "deterministic-fallback",
        "model": "rules-v1",
        "risk_explanation": f"The message is {level} risk at {score}/100 based on observable forensic signals; this is an investigative assessment, not proof of sender identity.",
        "why_this_risk": reasons[:8] or ["No high-weight deterministic signal was recorded."],
        "recommended_actions": ["Review cited evidence and provider authentication results.", "Do not execute or open untrusted attachments."] if score < 50 else ["Keep the message quarantined pending analyst review.", "Preserve the original evidence hash and provider message ID."],
        "evidence_citations": sorted({item for item in citations if item}),
        "uncertainty": "External reputation, sandbox execution, and full mailbox context are not asserted by this local explanation.",
    }


def explain_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    evidence = minimized_evidence(analysis)
    provider = os.getenv("LLM_PROVIDER", "fallback").lower()
    if provider != "ollama":
        return _fallback(evidence)
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    prompt = "Return JSON with keys risk_explanation, why_this_risk, recommended_actions, evidence_citations, uncertainty. Cite only evidence IDs. Never infer identity.\n" + json.dumps(evidence, ensure_ascii=False)
    request = urllib.request.Request(f"{base_url}/api/generate", data=json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "15"))) as response:
            raw = json.loads(response.read().decode("utf-8"))
        result = json.loads(raw.get("response", "{}"))
        if not isinstance(result, dict):
            raise ValueError("non-object explanation")
        result.update({"provider": "ollama", "model": model})
        return result
    except (OSError, ValueError, json.JSONDecodeError):
        fallback = _fallback(evidence)
        fallback["provider"] = "deterministic-fallback-after-ollama-error"
        return fallback


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Explain a stored MailTrace analysis using Ollama or the deterministic fallback.")
    parser.add_argument("--analysis", help="path to a JSON analysis result; reads stdin when omitted")
    args = parser.parse_args()
    source = open(args.analysis, "r", encoding="utf-8") if args.analysis else sys.stdin
    try:
        print(json.dumps(explain_analysis(json.load(source)), indent=2, ensure_ascii=False))
    finally:
        if args.analysis:
            source.close()
