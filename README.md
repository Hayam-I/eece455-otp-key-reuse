
# OTP key reuse

EECE 455/632 project 2: VENONA and one-time-pad key reuse.

This repo has the OTP implementation, the two experiments (one key for all
messages vs. a separate key for each message) and the statistics for section 4
of the report. The crib-dragging scripts read the ciphertext files that are
produced here.

## Setup

Python 3.10 or newer (tested with 3.11.9).

```bash
pip install -r requirements.txt
```

## Running

```bash
python run_all.py
```

Encrypts the six messages in `data/corpus.json`, writes the two ciphertext
files and puts all tables and figures in `results/`. The keys come from a
seeded generator (seed 455), so everybody gets exactly the same files and the
same numbers.

The ciphertext files are frozen. Running the script again reproduces them
byte for byte, so `git status` should not show them as modified. If it does,
the corpus or the seed was changed: tell the group before committing.

```bash
python run_all.py --fresh
```

Same experiments with new keys from the OS random generator (`secrets`).
Output goes to `fresh_run/` so the frozen files are not touched. The reuse
numbers are identical to the normal run because the key cancels in
C1 XOR C2. Only the control numbers move a little.

```bash
python -m unittest -v
```

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
- `results/xor_identity.csv` - C1 XOR C2 = P1 XOR P2 check for every pair
- `results/chi_square.csv` - chi-square against uniform, reuse and control
- `results/xor_classes.csv` - share of positions in each XOR class
- `results/xor_histogram.csv` - the raw histogram behind the first figure
- `results/pair_types.csv` - which kinds of characters meet (from the plaintexts)
- `results/class_sources.csv` - which character pairs end up in each XOR class
- `results/fig_xor_histogram.png`, `results/fig_xor_classes.png` - figures

## Ciphertext file format

Both ciphertext files have this format. There is no plaintext and no key in
them, and `run_all.py` refuses to write a file with any other field.

```json
{
  "set": "reuse",
  "messages": [
    {"id": "m1", "ciphertext_hex": "..."},
    {"id": "m2", "ciphertext_hex": "..."}
  ]
}
```

`"set"` is `"reuse"` or `"control"`. The ids are the same as in the corpus.

## Predicted class shares

`data/predictions.json` has the predictions from section 3.4 of the report,
one set for each space probability s (0.15, 0.18, 0.20). They are printed
next to the measured shares, and the second figure draws the s=0.18 one.

Class names: `zero` (0x00), `same_case` (0x01-0x1F), `opposite_case`
(0x20-0x3F), `space_lower` (0x41-0x5A), `space_upper` (0x61-0x7A),
`other_low` (the rest below 0x80), `high_bit` (0x80-0xFF).

The numbers are taken from the table in section 3.4 like this:

- `zero` = identical letters + space XOR space
- `same_case` = letter XOR letter - identical letters
- `space_lower` = space XOR letter
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

## Crib-dragging

This repository also includes an implementation of a crib-dragging attack
against the reused-key ciphertexts.

When two messages are encrypted using the same one-time-pad key, XORing their
ciphertexts cancels the key:

`C1 XOR C2 = P1 XOR P2`

This allows candidate plaintext fragments, known as cribs, to be tested at
different offsets. If a candidate produces plausible text in one message,
it provides information about the corresponding position in the other
message.

The implementation evaluates crib placement, compares reused-key ciphertexts
against an independent-key control, and performs iterative automatic
plaintext recovery.

### Implementation files

- `config.py` - configuration and paths for input data and output files
- `crib_drag.py` - crib-dragging operations and candidate-offset evaluation
- `scoring.py` - scoring of candidate plaintexts and crib placements
- `evaluate.py` - runs the experiments and generates the results
- `test_crib_drag.py` - tests for the crib-dragging implementation
- `make_dummy.py` - creates dummy data for testing
- `data/hand_example.json` - small example dataset for demonstrating the attack
- `walkthrough.txt` - walkthrough of the implementation and attack

The implementation uses the existing project data:

- `data/ciphertexts.json` - reused-key ciphertext set
- `data/ciphertexts_control.json` - independent-key control set
- `data/corpus.json` - plaintext ground truth used for evaluating recovery

The original ciphertext files should be reused as inputs. Dummy data should
not replace the original ciphertexts when running the actual experiments.

### Running the crib-dragging experiments

Install the dependencies from the repository root:

```bash
pip install -r requirements.txt
```

Run the evaluation:

```bash
python evaluate.py
```

The evaluation uses the data and output paths specified in `config.py`.
For the real-data evaluation, the output directory is `results/real/`.

The evaluation generates experiment summaries, CSV files, and figures in
this directory. The `real` directory is separate from the original results
stored directly under `results/`.

To run the tests:

```bash
python -m unittest -v
```

To generate dummy data for testing:

```bash
python make_dummy.py
```

Dummy data is intended for testing and demonstration. It should not be used
as a replacement for the original ciphertexts when reporting the experimental
results.

### Experiments

**Crib length**

This experiment evaluates how the length of a known plaintext fragment
affects the ability to identify its correct position in the reused-key
ciphertexts. It compares common and rare cribs and reports top-1 and top-3
success rates.

Longer cribs generally provide more information and make it easier to
distinguish the correct offset from incorrect candidate offsets.

**Number of ciphertexts**

This experiment evaluates how the number of ciphertexts encrypted with the
same key affects crib-placement accuracy. The evaluation uses a six-character
crib and compares configurations containing different numbers of ciphertexts.

The independent-key control is included to show that the same attack does
not produce comparable results when each message is encrypted with a
separate key.

**Automatic plaintext recovery**

This experiment evaluates iterative recovery of plaintext characters from
the reused-key ciphertexts. The algorithm proposes candidate characters,
scores them, and uses accepted candidates to support further recovery rounds.

The evaluation reports the number and fraction of correctly recovered
positions, the number of incorrect recoveries, precision, and the number of
recovery rounds.

Automatic recovery does not necessarily reconstruct every complete message.
Some positions may require additional analyst-assisted guesses, while
positions that are not covered by another ciphertext cannot be recovered
through pairwise key cancellation alone.

### Results

The real-data evaluation uses six messages with lengths of 197, 98, 400, 158,
319, and 266 characters, for a total of 1,438 characters.

A total of 1,357 positions are covered by at least two ciphertexts. The
remaining 81 positions at the end of the longest message are not covered by
another ciphertext and therefore cannot be recovered using this key-reuse
relationship.

The experiments show that:

- Crib-placement success improves as crib length increases.
- Using more ciphertexts improves the ability to identify correct crib
  positions.
- The independent-key control remains close to chance-level performance.
- Automatic recovery improves as more reused-key ciphertexts are available.
- Automatic recovery alone does not complete all six messages; additional
  analyst-assisted guesses are needed.

For the six-ciphertext configuration, the automatic recovery procedure
recovers 1,061 of the 1,357 overlapping positions correctly, corresponding
to 78.2% recovery. It makes 12 incorrect recoveries, giving a precision of
98.9%.

The evaluation also includes an ablation study comparing the full recovery
procedure with variations that remove or add individual heuristics. These
results are used to assess the contribution of the different components of
the recovery algorithm.

### Generated outputs

The real-data evaluation generates the following figures in `results/real/`:

- `fig1_success_vs_crib_length.png` - crib-placement success as a function
  of crib length
- `fig2_success_vs_num_ciphertexts.png` - crib-placement success as a
  function of the number of ciphertexts
- `fig3_recovery_per_round.png` - fraction of plaintext positions correctly
  recovered over successive recovery rounds

The directory also contains summary and CSV output files with the numerical
results of the experiments.

The resulting directory structure is:

```text
results/
├── summary.txt
├── xor_identity.csv
├── chi_square.csv
├── xor_classes.csv
├── xor_histogram.csv
├── pair_types.csv
├── class_sources.csv
├── fig_xor_histogram.png
├── fig_xor_classes.png
└── real/
    ├── summary.txt
    ├── fig1_success_vs_crib_length.png
    ├── fig2_success_vs_num_ciphertexts.png
    ├── fig3_recovery_per_round.png
    └── other CSV output files
```

### Relationship between the experiments

The statistical experiments examine evidence of one-time-pad key reuse by
comparing the XOR of ciphertexts and the distributions of the resulting
byte values.

The crib-dragging implementation builds on the same reused-key ciphertexts
and demonstrates how the relationship

`C1 XOR C2 = P1 XOR P2`

can be exploited to identify candidate plaintext fragments and recover
plaintext characters.

Both parts use the same frozen ciphertext files. The independent-key control
provides a comparison for evaluating whether the observed results are caused
by key reuse rather than by the attack procedure itself.
