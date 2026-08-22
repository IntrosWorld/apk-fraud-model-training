"""Train and evaluate an APK-derived static malware classifier."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold


IDENTITY_COLUMNS = {"sha256", "label", "family", "group_id", "source", "source_member", "analysis_quality"}
LIST_COLUMNS = {
    "permissions": "perm",
    "dangerous_permissions": "dangerous_perm",
    "api_families": "api",
    "yara_rules": "yara",
    "obfuscation_signals": "obfuscation",
    "certificate_flags": "certificate_flag",
    "apkid_categories": "apkid",
    "financial_keywords": "financial_keyword",
}


def load_rows(path: Path):
    records, labels, groups = [], [], []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            features = {}
            for key, value in row.items():
                if key in IDENTITY_COLUMNS or key in LIST_COLUMNS:
                    continue
                try:
                    features[key] = float(value or 0)
                except ValueError:
                    continue
            for column, prefix in LIST_COLUMNS.items():
                for token in json.loads(row.get(column) or "[]"):
                    features[f"{prefix}={token}"] = 1.0
            records.append(features)
            labels.append(int(row["label"]))
            groups.append(row.get("group_id") or row["sha256"])
    return records, np.asarray(labels), np.asarray(groups)


def grouped_splits(labels, groups, seed):
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    train_val, test = next(outer.split(np.zeros(len(labels)), labels, groups))
    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=seed + 1)
    train_rel, val_rel = next(inner.split(np.zeros(len(train_val)), labels[train_val], groups[train_val]))
    return train_val[train_rel], train_val[val_rel], test


def operating_threshold(labels, probabilities, min_specificity=0.90):
    best = (1.0, -1.0)
    for threshold in np.unique(np.r_[probabilities, 0.5, 1.0]):
        pred = probabilities >= threshold
        tn, fp, fn, tp = confusion_matrix(labels, pred, labels=[0, 1]).ravel()
        specificity = tn / max(1, tn + fp)
        score = f1_score(labels, pred, zero_division=0)
        if specificity >= min_specificity and score > best[1]:
            best = (float(threshold), float(score))
    return best[0]


def metrics(labels, probabilities, threshold):
    pred = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(labels, pred),
        "balanced_accuracy": balanced_accuracy_score(labels, pred),
        "precision": precision_score(labels, pred, zero_division=0),
        "recall": recall_score(labels, pred, zero_division=0),
        "specificity": tn / max(1, tn + fp),
        "f1": f1_score(labels, pred, zero_division=0),
        "roc_auc": roc_auc_score(labels, probabilities),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--seed", type=int, default=2020)
    parser.add_argument("--minimum-specificity", type=float, default=0.90)
    args = parser.parse_args()
    records, labels, groups = load_rows(args.data)
    if len(records) < 40 or len(np.unique(labels)) != 2:
        raise ValueError("Need at least 40 rows containing both benign and malware labels")
    train_idx, val_idx, test_idx = grouped_splits(labels, groups, args.seed)
    vectorizer = DictVectorizer(sparse=True)
    x_train = vectorizer.fit_transform([records[i] for i in train_idx])
    x_val = vectorizer.transform([records[i] for i in val_idx])
    x_test = vectorizer.transform([records[i] for i in test_idx])
    candidates = {
        "extra_trees": ExtraTreesClassifier(n_estimators=500, class_weight="balanced", min_samples_leaf=2, random_state=args.seed, n_jobs=-1),
        "random_forest": RandomForestClassifier(n_estimators=500, class_weight="balanced", min_samples_leaf=2, random_state=args.seed, n_jobs=-1),
    }
    trials = {}
    selected = None
    selected_score = -1.0
    selected_threshold = 1.0
    for name, model in candidates.items():
        model.fit(x_train, labels[train_idx])
        probability = model.predict_proba(x_val)[:, 1]
        threshold = operating_threshold(labels[val_idx], probability, args.minimum_specificity)
        result = metrics(labels[val_idx], probability, threshold)
        trials[name] = {"threshold": threshold, "validation": result}
        if result["balanced_accuracy"] > selected_score:
            selected, selected_score, selected_threshold = model, result["balanced_accuracy"], threshold
            selected_name = name
    test_probability = selected.predict_proba(x_test)[:, 1]
    test_metrics = metrics(labels[test_idx], test_probability, selected_threshold)
    report = {
        "selected_model": selected_name,
        "operating_threshold": selected_threshold,
        "minimum_specificity_policy": args.minimum_specificity,
        "rows": len(records),
        "feature_count": len(vectorizer.feature_names_),
        "split": {"train": len(train_idx), "validation": len(val_idx), "test": len(test_idx), "strategy": "stratified_group"},
        "candidate_validation": trials,
        "held_out_test": test_metrics,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    bundle = {
        "model": selected,
        "vectorizer": vectorizer,
        "operating_threshold": selected_threshold,
        "metrics": report,
        "schema_version": 1,
        "feature_kind": "apk_static_evidence",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.output_dir / "apk_static_model.joblib")
    (args.output_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
