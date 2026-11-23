"""Merge our own texts with the public set into classifier/data/combined.csv.

Public set: deepset/prompt-injections (Apache 2.0), https://huggingface.co/datasets/deepset/prompt-injections
Only English rows of the public set are kept.
Splits:
  public train -> train
  public test  -> test_public   (a different style of text than ours: an honest outside check)
  our own texts -> train / test_local, split by the first three words so reworded variants stay together
Run from the project root:  python -I classifier/prepare_data.py
"""
import csv
import hashlib
import re
from pathlib import Path

import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'classifier'))
from app.core.detectors import detect_prompt_injection  # noqa: E402
import india_extra  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
rows, seen, dropped, noisy = [], set(), [], []
HIJACK = re.compile(r"forget|ignore|disregard|abandon|drop all|stop[:\s-]|new (?:task|instruction|statement|assignment)|previous|above|preceding|prior|instruction|prompt|act as|you are now|you are the|pretend|from now on|spell.?check|repeat after|print|embedding|do not answer|don.?t answer|ignore all|film about|role-?play|now you are|your own knowledge and not|provided context|very well done|very good\.|simply great|new challenge|hello gpt", re.I)

EN = set("the and you is are to of that it for with this as on be have not what your i will can from".split())
OTHER = set("der die das und ich nicht wie ist für mit eine ein sie zu auf den dem von es auch wir le la les est pour une des que qui dans pas vous je nous el los las para por con que se".split())


def is_english(text):
    """Rough filter for the public set only: German/French/Spanish stopwords must not outnumber English ones."""
    if re.search(r"[äöüßéèêàçñ]", text.lower()):
        return False
    words = re.findall(r"[a-zäöüßéèêàçñ']+", text.lower())
    return sum(w in EN for w in words) >= sum(w in OTHER for w in words)


def add(text, label, source, split):
    text = " ".join(str(text).split())
    if not text or text.lower() in seen:
        return
    seen.add(text.lower())
    rows.append((text, int(label), source, split))


for name, split in (("train", "train"), ("test", "test_public")):
    for text, label in pd.read_parquet(DATA / "raw" / f"{name}.parquet")[["text", "label"]].itertuples(index=False):
        words = str(text).split()
        if not is_english(text) or (label == 0 and len(words) <= 6 and "?" not in text):
            dropped.append(text)  # not English, or a bare topic title that no user would type as a prompt
        elif label == 1 and not (HIJACK.search(text) or detect_prompt_injection(text)):
            noisy.append(text)  # labelled attack, but it has no instruction to override, extract or take over
        else:
            add(text, label, "deepset", split)

with open(DATA / "local.csv", newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        group = " ".join(re.findall(r"[a-z0-9]+", r["text"].lower())[:3])
        bucket = int(hashlib.md5(group.encode()).hexdigest(), 16) % 10
        add(r["text"], r["label"], r["source"], "test_local" if bucket < 3 else "train")

for label, texts, source in ((0, india_extra.NORMAL, "india_extra_normal"), (1, india_extra.ATTACK, "india_extra_attack")):
    for text in texts:
        group = " ".join(re.findall(r"[a-z0-9]+", text.lower())[:3])
        bucket = int(hashlib.md5(group.encode()).hexdigest(), 16) % 10
        add(text, label, source, "test_local" if bucket < 3 else "train")

with open(DATA / "combined.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["text", "label", "source", "split"])
    w.writerows(rows)

df = pd.DataFrame(rows, columns=["text", "label", "source", "split"])
print(df.groupby(["split", "label"]).size().unstack(fill_value=0).rename(columns={0: "normal", 1: "attack"}))
print("total", len(df), "| dropped (non-English or bare titles):", len(dropped), "| dropped as not-an-attack-for-us:", len(noisy))
print("--- label-1 rows dropped as noisy ---")
for t in noisy:
    print("  ", t[:90])
