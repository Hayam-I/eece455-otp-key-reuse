"""config.py - the single place where data paths live.

At Milestone 1, switch from dummy to real data with ONE line:
    DATA_MODE = "real"
(or run with the environment variable OTP_DATA_MODE=real).
Adjust the "real" paths below to match repository layout.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

DATA_MODE = os.environ.get("OTP_DATA_MODE", "real")   # <- the one-line switch ("dummy" or "real")

PATHS = {
    "dummy": {
        "reuse": ROOT / "data" / "dummy" / "ciphertexts_reuse.json",
        "control": ROOT / "data" / "dummy" / "ciphertexts_control.json",
        "corpus": ROOT / "data" / "dummy" / "corpus_dummy.json",   # scoring only
    },
    "real": {
        "reuse": ROOT / "data" / "ciphertexts.json",            # reuse set
        "control": ROOT / "data" / "ciphertexts_control.json",  # independent-key set
        "corpus": ROOT / "data" / "corpus.json",                # ground truth, evaluate.py only
    },
}

SEED = 20261123          # fixed seed for trial subsampling (not for keys)
RESULTS_DIR = ROOT / "results" / DATA_MODE
