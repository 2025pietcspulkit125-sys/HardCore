"""Small offline, transparent classifier for demo-time email triage."""
import json
import math
import os
import re
from pathlib import Path

TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
BUNDLED_ARTIFACT_PATH = Path(__file__).resolve().parent / "ml_data" / "model_artifact.json"
ARTIFACT_PATH = Path(os.getenv("ML_MODEL_PATH") or BUNDLED_ARTIFACT_PATH)

def _tokens(text):
    return TOKEN_RE.findall((text or "").lower())

def _load_artifact():
    try:
        with ARTIFACT_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"labels": [], "term_counts": {}, "term_totals": {}, "vocabulary": [], "validation_metrics": {}}


MODEL = _load_artifact()
LABELS = MODEL.get("labels") or ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION", "BEC_FRAUD", "MALWARE"]
TERM_COUNTS = MODEL.get("term_counts") or {}
TERM_TOTALS = MODEL.get("term_totals") or {}
VOCABULARY = set(MODEL.get("vocabulary") or [])

def classify(subject, body, sender, urls=None, attachments=None):
    text = " ".join([subject or "", body or "", sender or "", *(urls or []), *(attachments or [])])
    tokens = _tokens(text)
    scores = {}
    size = max(1, len(VOCABULARY))
    for label in LABELS:
        score = math.log(1 / len(LABELS))
        denominator = TERM_TOTALS[label] + size
        for token in tokens:
            score += math.log((TERM_COUNTS.get(label, {}).get(token, 0) + 1) / denominator)
        scores[label] = score
    best = max(scores, key=scores.get)
    peak = scores[best]
    probabilities = {label: math.exp(score - peak) for label, score in scores.items()}
    total_probability = sum(probabilities.values()) or 1
    probabilities = {label: round(value / total_probability, 4) for label, value in probabilities.items()}
    confidence = probabilities[best]
    return {
        "ml_classification": best,
        "ml_confidence": round(confidence, 4),
        "ml_probabilities": probabilities,
        "ml_features_used": ["subject", "body", "sender", "urls", "attachments", "token-likelihoods"],
        "ml_model": MODEL.get("model", "bundled-local-multinomial-demo-classifier"),
        "model_version": MODEL.get("model_version", MODEL.get("model", "unknown")),
        "dataset_version": MODEL.get("dataset_version", "unknown"),
        "ml_validation_metrics": MODEL.get("validation_metrics", {}),
        "ml_disclaimer": "Locally trained lightweight classifier suitable for prototype/SIH demonstration; it does not represent real-world threat prevalence.",
    }
