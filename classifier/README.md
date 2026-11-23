# Experimental intent classifier

Optional second opinion, used only when a request sends `?classifier=true`. Rules still win: it can only add risk.

**Retrain** (needs `pip install scikit-learn pandas pyarrow`, training only):

1. `python -I classifier/build_local_data.py` and `python -I classifier/prepare_data.py` build `classifier/data/combined.csv`
   from our own texts plus the public set below (English rows only). Put the raw files in `classifier/data/raw/` (deepset) and `classifier/data/raw_notinject/` (NotInject) first.
2. `python classifier/train.py` trains, picks the threshold by cross-validation (at most 3% harmless text flagged),
   checks that the exported plain-Python scorer matches scikit-learn, writes `app/core/intent_weights.json` and prints the comparison tables.

**Data**
- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), Apache 2.0: attack and normal prompts. Some of its attack rows are task hijacks rather than security attacks, so its labels are noisy.
- [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject), MIT (from the InjecGuard paper): harmless sentences that contain attack-style trigger words. English rows only.
- `intent_data.py`, written for this project: harmless questions about attack phrases, attacks of several kinds (override, role-play, extraction, authority claim, hypothetical framing, completion trick, tool abuse, planted document text, Hinglish), and a 40-clause held-out test set that is never used for training.
- `india_extra.py`: Indian-context normal and attack texts.

Raw data and the CSVs are not committed (`classifier/data/` is ignored). The trained weights are.
