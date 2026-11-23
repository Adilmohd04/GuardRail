"""Train the experimental intent classifier and export app/core/intent_weights.json.

Run from the project root:  python classifier/train.py
Needs scikit-learn (training only; the API scores with plain Python, see app/core/intent_model.py).

Honest reporting: the threshold is chosen by cross-validation on the training data, then the
held-out TEST set in intent_data.py is scored once. The numbers are printed, not hidden.
"""
import json
import os
import re
import sys

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from app.core.detectors import detect_prompt_injection  # noqa: E402
from classifier.intent_data import DIRECTIVE_TRAIN, INFO_TRAIN, TEST  # noqa: E402
from app.core.intent_model import IntentModel, features  # noqa: E402

DATA = os.path.join(ROOT, "classifier", "data")
OUT = os.path.join(ROOT, "app", "core", "intent_weights.json")
MAX_FALSE_ALARM = 0.03  # harmless text flagged, measured by cross-validation


def words(text):
    return set(re.findall(r"\w+", text.lower()))


def load_training():
    combined = pd.read_csv(os.path.join(DATA, "combined.csv"))
    train = combined[combined.split == "train"]
    rows = list(zip(train.text, train.label.astype(int)))
    notinject = pd.concat(
        pd.read_parquet(os.path.join(DATA, "raw_notinject", f"{n}.parquet")) for n in ("one", "two", "three")
    )
    rows += [(t, 0) for t in notinject[notinject.category != "Multilingual"].prompt]  # English only
    rows += [(t, 0) for t in INFO_TRAIN] + [(t, 1) for t in DIRECTIVE_TRAIN]
    held_out = [words(t) for t, _ in TEST]
    keep = [(t, y) for t, y in rows if not any(len(words(t) & h) / len(words(t) | h) >= 0.6 for h in held_out)]
    print(f"training rows: {len(keep)} ({len(rows) - len(keep)} dropped as near-copies of the test set)")
    local = combined[combined.split != "train"]
    return keep, list(zip(local.text, local.label.astype(int)))


def pick_threshold(y, prob):
    best = 0.5
    for t in np.arange(0.30, 0.91, 0.01):
        flagged = prob >= t
        if flagged[y == 0].mean() <= MAX_FALSE_ALARM:
            return round(float(t), 2)  # lowest threshold that keeps false alarms low = most attacks caught
    return best


def table(name, items, model):
    y = np.array([label for _, label in items])
    rules = np.array([bool(detect_prompt_injection(t)) for t, _ in items])
    clf = np.array([model.score(t) >= model.threshold for t, _ in items])
    print(f"\n{name} ({int(y.sum())} attacks, {int((y == 0).sum())} harmless)")
    for label, pred in (("rules only", rules), ("classifier only", clf), ("rules + classifier", rules | clf)):
        print(f"  {label:20s} caught {int((pred & (y == 1)).sum()):3d}/{int(y.sum())}   false alarms {int((pred & (y == 0)).sum()):3d}/{int((y == 0).sum())}")


def main():
    rows, local = load_training()
    texts, y = [t for t, _ in rows], np.array([label for _, label in rows])
    vec = TfidfVectorizer(analyzer=lambda t: sorted(features(t)), min_df=2)
    X = vec.fit_transform(texts)
    # C picked by cross-validation; class_weight keeps the smaller attack class from being ignored.
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    best = None
    for C in (0.3, 1, 3, 10, 30):
        prob = cross_val_predict(LogisticRegression(C=C, class_weight="balanced", max_iter=2000), X, y, cv=cv, method="predict_proba")[:, 1]
        t = pick_threshold(y, prob)
        caught = (prob >= t)[y == 1].mean()
        print(f"C={C:<5} cross-validated: threshold {t:.2f}, attacks caught {caught:.0%}")
        if best is None or caught > best[0]:
            best = (caught, C, t)
    _, C, threshold = best
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=2000).fit(X, y)
    data = {
        "vocab": {f: i for f, i in vec.vocabulary_.items()},
        "idf": [round(float(v), 5) for v in vec.idf_],
        "coef": [round(float(v), 5) for v in clf.coef_[0]],
        "bias": round(float(clf.intercept_[0]), 5),
        "threshold": threshold,
    }
    data["vocab"] = {f: int(i) for f, i in data["vocab"].items()}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    model = IntentModel(data)
    # The plain-Python scorer must agree with scikit-learn, or the exported file is wrong.
    ref = clf.predict_proba(vec.transform(texts[:50]))[:, 1]
    mine = np.array([model.probability(t) for t in texts[:50]])
    assert np.allclose(ref, mine, atol=1e-3), "exported scorer disagrees with scikit-learn"
    print(f"\nchosen C={C}, threshold {threshold}; wrote {OUT} ({os.path.getsize(OUT) // 1024} KB)")
    table("HELD-OUT TEST (written after the rules, wordings the rules do not list)", TEST, model)
    table("LOCAL + PUBLIC TEST SPLITS (rules were tuned on this kind of text, so they look strong here)", local, model)


if __name__ == "__main__":
    main()
