# OTP key reuse

EECE 455/632 project 2: VENONA and one-time-pad key reuse.

This repo has the OTP implementation, the two experiments (one key for all
messages vs. a separate key for each message) and the statistics for section 4
of the report. The crib-dragging scripts read the ciphertext files that are
produced here.

## Setup

Python 3.10 or newer (tested with 3.11.9).

    pip install -r requirements.txt

## Running

    python run_all.py

Encrypts the six messages in `data/corpus.json`, writes the two ciphertext
files and puts all tables and figures in `results/`. The keys come from a
seeded generator (seed 455), so everybody gets exactly the same files and the
same numbers.

The ciphertext files are frozen. Running the script again reproduces them
byte for byte, so `git status` should not show them as modified. If it does,
the corpus or the seed was changed: tell the group before committing.

    python run_all.py --fresh

Same experiments with new keys from the OS random generator (`secrets`).
Output goes to `fresh_run/` so the frozen files are not touched. The reuse
numbers are identical to the normal run because the key cancels in
C1 xor C2. Only the control numbers move a little.

    python -m unittest -v

Runs the tests.

## Files

- `otp_lib.py` - key generation, encrypt/decrypt and the `OneTimePad` pad
  manager (refuses to reuse key bytes unless `allow_reuse=True`)
- `run_all.py` - the reuse and control experiments, statistics, figures
- `test_otp.py` - tests
- `data/corpus.json` - the six plaintexts (ground truth, only for scoring)
- `data/ciphertexts.json` - reuse set, one key for all six messages
- `data/ciphertexts_control.json` - control set, one key per message
- `data/predictions.json` - predicted class shares from section 3.4
- `results/summary.txt` - everything the script prints
- `results/xor_identity.csv` - C1 xor C2 = P1 xor P2 check for every pair
- `results/chi_square.csv` - chi-square against uniform, reuse and control
- `results/xor_classes.csv` - share of positions in each XOR class
- `results/xor_histogram.csv` - the raw histogram behind the first figure
- `results/pair_types.csv` - which kinds of characters meet (from the plaintexts)
- `results/class_sources.csv` - which character pairs end up in each XOR class
- `results/fig_xor_histogram.png`, `results/fig_xor_classes.png` - figures

## Ciphertext file format

Both ciphertext files have this format. There is no plaintext and no key in
them, and `run_all.py` refuses to write a file with any other field.

    {
      "set": "reuse",
      "messages": [
        {"id": "m1", "ciphertext_hex": "..."},
        {"id": "m2", "ciphertext_hex": "..."}
      ]
    }

`"set"` is `"reuse"` or `"control"`. The ids are the same as in the corpus.

## Predicted class shares

`data/predictions.json` has the predictions from section 3.4 of the report,
one set for each space probability s (0.15, 0.18, 0.20). They are printed
next to the measured shares, and the second figure draws the s=0.18 one.

Class names: `zero` (0x00), `same_case` (0x01-0x1F), `opposite_case`
(0x20-0x3F), `space_lower` (0x41-0x5A), `space_upper` (0x61-0x7A),
`other_low` (the rest below 0x80), `high_bit` (0x80-0xFF).

The numbers are taken from the table in section 3.4 like this:

- `zero` = identical letters + space xor space
- `same_case` = letter xor letter - identical letters
- `space_lower` = space xor letter
- everything else = 0, because the model only has lowercase letters and
  spaces (the three shares above already add up to 1)

## Notes

- All messages are aligned at byte 0 and only the overlapping part of each
  pair is analysed. The end of the longest message is covered by key bytes
  that nothing else used, so that part is still secure.
- The seeded generator is only there to make the demo data reproducible. It
  is not a valid OTP key source. `generate_key()` uses `secrets` by default.
- The chi-square values are computed over all 15 pairs together. The pairs
  share messages, so the samples are not completely independent. That is why
  the control is also repeated 1000 times with new keys: it shows the range
  of values to expect when no key is reused.
