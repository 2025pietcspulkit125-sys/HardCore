"""Reproducible CPU-only email risk classifier training utility.

The bundled corpus is explicitly synthetic seed data. Validation never includes
augmentation rows unless a caller deliberately creates a separate dataset.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "ml_data" / "training_data.json"
ARTIFACT = ROOT / "ml_data" / "model_artifact.json"
LABELS = ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "IMPERSONATION", "BEC_FRAUD", "MALWARE"]
TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall((text or "").lower())


def augment(rows: list[dict]) -> list[dict]:
    additions = []
    templates = {
        "LEGITIMATE": ["normal team update shared calendar information", "customer receipt reference and delivery status"],
        "SUSPICIOUS": ["unexpected security notice review account activity", "external sender asks for unusual confirmation"],
        "PHISHING": ["verify login credentials immediately account suspended", "secure portal password reset confirmation link"],
        "IMPERSONATION": ["executive display name confidential urgent request", "brand support identity mismatch reply address"],
        "BEC_FRAUD": ["urgent wire transfer beneficiary change invoice payment", "finance request gift cards confidential bank details"],
        "MALWARE": ["macro enabled document archive script payload", "executable attachment compressed file run content"],
    }
    for label, values in templates.items():
        for text in values:
            additions.append({"label": label, "text": text, "synthetic": True, "source": "augmentation"})
    return rows + additions


def fit(rows: list[dict]) -> dict:
    term_counts = {label: Counter() for label in LABELS}
    term_totals = Counter()
    label_counts = Counter()
    vocabulary: set[str] = set()
    for row in rows:
        label = row.get("label")
        if label not in LABELS:
            continue
        values = tokens(row.get("text", ""))
        vocabulary.update(values)
        term_counts[label].update(values)
        term_totals[label] += len(values)
        label_counts[label] += 1
    return {"labels": LABELS, "term_counts": {label: dict(term_counts[label]) for label in LABELS}, "term_totals": dict(term_totals), "label_counts": dict(label_counts), "vocabulary": sorted(vocabulary), "model": "mailtrace-local-multinomial-v2", "model_version": "mailtrace-local-multinomial-v2", "dataset_version": "seed-synthetic-2026-09-23"}


def predict(artifact: dict, text: str) -> str:
    values = tokens(text)
    size = max(1, len(artifact.get("vocabulary", [])))
    labels = artifact.get("labels") or LABELS
    scores = {}
    for label in labels:
        prior = (artifact.get("label_counts", {}).get(label, 1) or 1) / max(1, sum(artifact.get("label_counts", {}).values()))
        denominator = artifact.get("term_totals", {}).get(label, 0) + size
        score = math.log(prior)
        for value in values:
            score += math.log((artifact.get("term_counts", {}).get(label, {}).get(value, 0) + 1) / denominator)
        scores[label] = score
    return max(scores, key=scores.get)


def metrics(artifact: dict, rows: list[dict]) -> dict:
    actual = [row.get("label") for row in rows]
    predictions = [predict(artifact, row.get("text", "")) for row in rows]
    per_class = {}
    confusion = {label: {other: 0 for other in LABELS} for label in LABELS}
    for expected, predicted in zip(actual, predictions):
        if expected in confusion and predicted in confusion[expected]:
            confusion[expected][predicted] += 1
    for label in LABELS:
        tp = sum(a == label and p == label for a, p in zip(actual, predictions))
        fp = sum(a != label and p == label for a, p in zip(actual, predictions))
        fn = sum(a == label and p != label for a, p in zip(actual, predictions))
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        per_class[label] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(2 * precision * recall / max(0.0001, precision + recall), 4), "support": sum(a == label for a in actual)}
    return {"accuracy": round(sum(a == p for a, p in zip(actual, predictions)) / max(1, len(actual)), 4), "macro": {key: round(sum(item[key] for item in per_class.values()) / len(per_class), 4) for key in ("precision", "recall", "f1")}, "per_class": per_class, "confusion_matrix": confusion, "validation_size": len(rows), "synthetic_validation": any(row.get("synthetic") for row in rows)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluate", action="store_true", help="print validation metrics")
    parser.add_argument("--predict", nargs="+", help="predict one sample phrase")
    parser.add_argument("--augment", action="store_true", help="add explicitly synthetic augmentation rows to training only")
    args = parser.parse_args()
    rows = json.loads(DATASET.read_text(encoding="utf-8"))
    validation = [row for index, row in enumerate(rows) if index % 3 == 2]
    training = [row for index, row in enumerate(rows) if index % 3 != 2]
    if args.augment:
        training = augment(training)
    artifact = fit(training)
    artifact["class_counts"] = {label: sum(row.get("label") == label for row in training) for label in LABELS}
    artifact["validation_metrics"] = metrics(artifact, validation)
    artifact["trained_at"] = datetime.now(timezone.utc).isoformat()
    ARTIFACT.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    if args.predict:
        print(json.dumps({"label": predict(artifact, " ".join(args.predict)), "model_version": artifact["model_version"]}, indent=2))
    if args.evaluate or not args.predict:
        print(json.dumps(artifact["validation_metrics"], indent=2))


if __name__ == "__main__":
    main()
