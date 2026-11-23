"""Collect the attack and normal texts we already wrote for the tests into one CSV.

Run from the project root:  python classifier/build_local_data.py
"""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests import test_india, test_redteam  # noqa: E402

# (module, list name, label, where it came from)
SOURCES = [
    (test_redteam, "ATTACK_PROMPTS", 1, "redteam_attack_prompt"),
    (test_redteam, "ATTACK_DOCS", 1, "redteam_attack_doc"),
    (test_redteam, "KNOWN_LIMITS", 1, "redteam_known_limit"),
    (test_india, "INDIAN_ATTACKS", 1, "india_attack"),
    (test_india, "MORE_ATTACKS", 1, "india_more_attack"),
    (test_india, "INTENT_ATTACKS", 1, "intent_attack"),
    (test_redteam, "BENIGN_PROMPTS", 0, "redteam_benign_prompt"),
    (test_redteam, "BENIGN_DOCS", 0, "redteam_benign_doc"),
    (test_india, "BENIGN_INDIAN_TEXT", 0, "india_benign"),
    (test_india, "NORMAL_TEXT", 0, "normal_text"),
    (test_india, "INTENT_BENIGN", 0, "intent_benign"),
]

rows, seen = [], set()
for module, name, label, source in SOURCES:
    for item in getattr(module, name):
        text = item[0] if isinstance(item, (tuple, list)) else item
        if not isinstance(text, str) or not text.strip() or text in seen:
            continue
        seen.add(text)
        rows.append((text, label, source))

out = ROOT / "classifier" / "data" / "local.csv"
with open(out, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["text", "label", "source"])
    writer.writerows(rows)

attacks = sum(1 for r in rows if r[1] == 1)
print(f"wrote {len(rows)} rows to {out}: {attacks} attack, {len(rows) - attacks} normal")
for _, name, label, source in SOURCES:
    print(f"  {source:24} {sum(1 for r in rows if r[2] == source)}")
