"""Tiny offline intent scorer: TF-IDF features and a logistic-regression table, in plain Python.

The weights come from classifier/train.py and sit in intent_weights.json next to this file.
Optional: the API uses it only when a request asks for it (POST /analyze?classifier=true).
"""
import json
import math
import os
import re

WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "intent_weights.json")
BLOCK_AT = 0.95  # at or above: block. Between the model threshold and this: flag for review (transform).


def features(text: str) -> set:
    """Words and word pairs (first 200 words). Training and scoring share this function."""
    words = re.findall(r"[^\W_]+", text.lower())[:200]
    return set(words) | {a + "_" + b for a, b in zip(words, words[1:])}


def clauses(text: str) -> list:
    return [c for c in re.split(r"(?<=[.?!;])\s+|\n+", text) if c.strip()]


class IntentModel:
    def __init__(self, data: dict):
        self.vocab, self.idf, self.coef = data["vocab"], data["idf"], data["coef"]
        self.bias, self.threshold = data["bias"], data["threshold"]

    def _terms(self, text: str):
        found = [(self.vocab[f], self.idf[self.vocab[f]]) for f in features(text) if f in self.vocab]
        norm = math.sqrt(sum(v * v for _, v in found)) or 1.0
        return [(i, v / norm) for i, v in found]

    def probability(self, text: str) -> float:
        z = self.bias + sum(self.coef[i] * v for i, v in self._terms(text))
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def score(self, text: str) -> float:
        """Highest attack probability over the whole text and each clause, so a command
        hidden after a harmless question still counts."""
        return max([self.probability(text)] + [self.probability(c) for c in clauses(text)[:20]])

    def top_words(self, text: str, n: int = 5) -> list:
        names = {i: f for f, i in self.vocab.items()}
        pushes = sorted(((self.coef[i] * v, names[i]) for i, v in self._terms(text)), reverse=True)
        return [name.replace("_", " ") for weight, name in pushes[:n] if weight > 0]


def load():
    """Return the model, or None if the weights file is missing (the UI then hides the toggle)."""
    try:
        with open(WEIGHTS_PATH, encoding="utf-8") as f:
            return IntentModel(json.load(f))
    except (OSError, ValueError, KeyError):
        return None
