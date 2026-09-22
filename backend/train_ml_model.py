"""Retrain the local MailTrace triage model.

Usage: backend/venv/Scripts/python.exe backend/train_ml_model.py
The dataset is synthetic and intended for SIH demonstration only.
"""

import json
import math
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "ml_data" / "training_data.json"
ARTIFACT = ROOT / "ml_data" / "model_artifact.json"
TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
LABELS = ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION", "BEC_FRAUD", "MALWARE"]


def tokens(text):
    return TOKEN_RE.findall((text or "").lower())


def fit(rows):
    term_counts = {label: Counter() for label in LABELS}
    term_totals = Counter()
    vocabulary = set()
    for row in rows:
        values = tokens(row["text"])
        vocabulary.update(values)
        term_counts[row["label"]].update(values)
        term_totals[row["label"]] += len(values)
    return {
        "labels": LABELS,
        "term_counts": {label: dict(term_counts[label]) for label in LABELS},
        "term_totals": dict(term_totals),
        "vocabulary": sorted(vocabulary),
        "model": "bundled-local-multinomial-demo-classifier",
    }


def predict(artifact, text):
    values = tokens(text)
    size = max(1, len(artifact["vocabulary"]))
    scores = {}
    for label in artifact["labels"]:
        denominator = artifact["term_totals"].get(label, 0) + size
        score = math.log(1 / len(artifact["labels"]))
        for value in values:
            score += math.log((artifact["term_counts"].get(label, {}).get(value, 0) + 1) / denominator)
        scores[label] = score
    return max(scores, key=scores.get)


def main():
    rows = json.loads(DATASET.read_text(encoding="utf-8"))
    validation = rows[2::3]
    training = [row for index, row in enumerate(rows) if index % 3 != 2]
    artifact = fit(training)
    predictions = [predict(artifact, row["text"]) for row in validation]
    actual = [row["label"] for row in validation]
    accuracy = sum(left == right for left, right in zip(actual, predictions)) / max(1, len(actual))
    metrics = {}
    for label in LABELS:
        tp = sum(a == label and p == label for a, p in zip(actual, predictions))
        fp = sum(a != label and p == label for a, p in zip(actual, predictions))
        fn = sum(a == label and p != label for a, p in zip(actual, predictions))
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        metrics[label] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(2 * precision * recall / max(0.0001, precision + recall), 4)}
    artifact["validation_metrics"] = {"accuracy": round(accuracy, 4), "macro": {key: round(sum(item[key] for item in metrics.values()) / len(metrics), 4) for key in ("precision", "recall", "f1")}, "per_class": metrics, "validation_size": len(validation)}
    ARTIFACT.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(json.dumps(artifact["validation_metrics"], indent=2))


if __name__ == "__main__":
    main()
