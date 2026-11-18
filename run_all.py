"""
Runs the two experiments and writes all the tables and figures.

    python run_all.py           normal run, fixed seed, same output every time
    python run_all.py --fresh   new random keys from the OS, output in fresh_run/

reuse set:    all six messages encrypted with the same key (aligned at byte 0)
control set:  the same messages, each one with its own key
"""

import argparse
import csv
import json
import math
import random
import re
import statistics
from collections import Counter
from itertools import combinations
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from otp_lib import KeyReuseError, OneTimePad, encrypt, generate_key, xor_overlap

HERE = Path(__file__).parent
DATA = HERE / "data"

SEED = 455        # only for the demo files, so the run can be reproduced
N_TRIALS = 1000   # repetitions of the control experiment for the chi-square check

REUSE_FILE = "ciphertexts.json"
CONTROL_FILE = "ciphertexts_control.json"

# Classes for the byte Ci xor Cj:
# (name, range as shown in the tables, usual cause, list of (low, high))
CLASSES = [
    ("zero", "0x00", "same character", [(0x00, 0x00)]),
    ("same_case", "0x01-0x1F", "two letters of the same case", [(0x01, 0x1F)]),
    ("opposite_case", "0x20-0x3F", "uppercase xor lowercase letter", [(0x20, 0x3F)]),
    ("space_lower", "0x41-0x5A", "space xor lowercase letter", [(0x41, 0x5A)]),
    ("space_upper", "0x61-0x7A", "space xor uppercase letter", [(0x61, 0x7A)]),
    ("other_low", "other below 0x80", "letter xor digit or punctuation",
     [(0x40, 0x40), (0x5B, 0x60), (0x7B, 0x7F)]),
    ("high_bit", "0x80-0xFF", "impossible for ASCII xor ASCII", [(0x80, 0xFF)]),
]


def load_corpus():
    """Read data/corpus.json and return {id: plaintext bytes}."""
    with open(DATA / "corpus.json", encoding="utf-8") as f:
        corpus = json.load(f)
    messages = {}
    for m in corpus["messages"]:
        text = m["plaintext"]
        if not (text.isascii() and text.isprintable()):
            raise ValueError(f"{m['id']} is not printable ASCII")
        if not 80 <= len(text) <= 400:
            raise ValueError(f"{m['id']} has {len(text)} characters, should be 80 to 400")
        messages[m["id"]] = text.encode("ascii")
    if len(messages) != 6:
        raise ValueError("the corpus should have six messages with different ids")
    return messages


def make_sets(messages, rng=None):
    """Encrypt the corpus twice: once with one shared key, once with separate keys."""
    longest = max(len(p) for p in messages.values())

    # reuse: one key as long as the longest message, every message starts at byte 0.
    # the pad only allows this because of allow_reuse=True
    pad = OneTimePad.generate(longest, allow_reuse=True, rng=rng)
    reuse = {mid: pad.encrypt(p, offset=0) for mid, p in messages.items()}

    # control: a new pad for each message, used once
    control = {mid: OneTimePad.generate(len(p), rng=rng).encrypt(p)
               for mid, p in messages.items()}
    return reuse, control


def to_contract(set_name, ciphertexts):
    return {
        "set": set_name,
        "messages": [{"id": mid, "ciphertext_hex": c.hex()} for mid, c in ciphertexts.items()],
    }


def check_contract(data):
    """Check a ciphertext file against the data contract, raise ValueError if it is off.

    Only the agreed fields are allowed, so a plaintext or a key cannot end up
    in the file by accident.
    """
    if not isinstance(data, dict) or set(data) != {"set", "messages"}:
        raise ValueError("file must have exactly the fields 'set' and 'messages'")
    if data["set"] not in ("reuse", "control"):
        raise ValueError("'set' must be 'reuse' or 'control'")
    if not isinstance(data["messages"], list) or not data["messages"]:
        raise ValueError("'messages' must be a non-empty list")
    ids = set()
    for m in data["messages"]:
        if not isinstance(m, dict) or set(m) != {"id", "ciphertext_hex"}:
            raise ValueError("a message must have exactly the fields 'id' and 'ciphertext_hex'")
        if not isinstance(m["id"], str) or m["id"] in ids:
            raise ValueError("message ids must be different strings")
        ids.add(m["id"])
        if not isinstance(m["ciphertext_hex"], str) or not re.fullmatch("([0-9a-f]{2})+", m["ciphertext_hex"]):
            raise ValueError(f"{m['id']}: ciphertext_hex is not a lowercase hex string")


def write_set(path, set_name, ciphertexts):
    data = to_contract(set_name, ciphertexts)
    check_contract(data)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def read_set(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    check_contract(data)
    return {m["id"]: bytes.fromhex(m["ciphertext_hex"]) for m in data["messages"]}


def identity_table(set_name, messages, ciphertexts):
    """For each pair of messages, count the positions where Ci xor Cj == Pi xor Pj."""
    rows = []
    for a, b in combinations(ciphertexts, 2):
        c_xor = xor_overlap(ciphertexts[a], ciphertexts[b])
        p_xor = xor_overlap(messages[a], messages[b])
        equal = sum(x == y for x, y in zip(c_xor, p_xor))
        rows.append({
            "set": set_name,
            "pair": f"{a}-{b}",
            "overlap": len(c_xor),
            "equal_positions": equal,
            "identity_holds": equal == len(c_xor),
        })
    return rows


def xor_histogram(texts):
    """Histogram (256 bins) of the bytes of Xi xor Xj over all pairs."""
    hist = [0] * 256
    for a, b in combinations(texts, 2):
        for byte in xor_overlap(a, b):
            hist[byte] += 1
    return hist


def chi_square(hist):
    """Chi-square statistic of the histogram against a uniform distribution."""
    expected = sum(hist) / 256
    return sum((count - expected) ** 2 for count in hist) / expected


def control_trials(messages, n, rng=None):
    """Repeat the control experiment n times and return the chi-square values.

    The 15 pairs share messages so the samples are not fully independent, and
    the chi-square(255) distribution is only an approximation here. Repeating
    the experiment shows directly what values to expect without key reuse.
    """
    values = []
    for _ in range(n):
        cts = [encrypt(p, generate_key(len(p), rng)) for p in messages.values()]
        values.append(chi_square(xor_histogram(cts)))
    return values


def class_count(hist, ranges):
    return sum(hist[v] for low, high in ranges for v in range(low, high + 1))


def char_type(byte):
    ch = chr(byte)
    if ch == " ":
        return "space"
    if ch.islower():
        return "lowercase"
    if ch.isupper():
        return "uppercase"
    if ch.isdigit():
        return "digit"
    return "punctuation"


def pair_types(messages):
    """From the plaintexts: which kinds of characters meet at each position."""
    counts = Counter()
    for a, b in combinations(messages.values(), 2):
        for x, y in zip(a, b):
            counts[" + ".join(sorted([char_type(x), char_type(y)]))] += 1
    return counts


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


# colours: reuse is blue and control is orange in both figures
BLUE, ORANGE, GREEN = "#2a78d6", "#eb6834", "#1baf7a"
BACKGROUND, DARK, GREY, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e1e0d9"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Segoe UI", "Arial", "DejaVu Sans"],
    "font.size": 10,
    "figure.facecolor": BACKGROUND,
    "axes.facecolor": BACKGROUND,
    "savefig.facecolor": BACKGROUND,
    "axes.edgecolor": "#c3c2b7",
    "axes.labelcolor": GREY,
    "xtick.color": GREY,
    "ytick.color": GREY,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def plot_histogram(hist_reuse, hist_control, chi_reuse, chi_control, path):
    expected = sum(hist_reuse) / 256
    fig, (top, bottom) = plt.subplots(2, 1, figsize=(9, 5.8), sharex=True, sharey=True)

    panels = [
        (top, hist_reuse, chi_reuse, BLUE, "Reused key: one key for all six messages"),
        (bottom, hist_control, chi_control, ORANGE, "Control: an independent key for every message"),
    ]
    for ax, hist, chi, colour, title in panels:
        ax.bar(range(256), hist, width=0.85, color=colour)
        ax.axhline(expected, color=GREY, linewidth=1)
        ax.set_title(title, loc="left", fontsize=11, fontweight="bold", color=DARK)
        ax.text(1.0, 1.03, f"chi-square = {chi:,.0f}", transform=ax.transAxes,
                ha="right", va="bottom", color=GREY)
        ax.set_ylabel("Positions")
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        ax.tick_params(length=0)

    # the right half of the top panel is empty, so the notes go there
    notes = [
        ("0x00", "same character"),
        ("0x01-0x1F", "two letters of the same case"),
        ("0x41-0x5A", "space xor lowercase letter"),
        ("0x80-0xFF", "never occurs: ASCII xor ASCII has top bit 0"),
    ]
    for i, (byte_range, meaning) in enumerate(notes):
        y = 0.90 - 0.105 * i
        top.text(0.53, y, byte_range, transform=top.transAxes, va="top", fontsize=9, color=DARK)
        top.text(0.645, y, meaning, transform=top.transAxes, va="top", fontsize=9, color=GREY)
    top.annotate(f"uniform: {expected:.1f} positions per value", xy=(254, expected),
                 xytext=(0, 5), textcoords="offset points",
                 ha="right", va="bottom", fontsize=9, color=GREY)

    ticks = [0, 32, 64, 96, 128, 160, 192, 224, 255]
    bottom.set_xticks(ticks)
    bottom.set_xticklabels([f"0x{t:02X}" for t in ticks])
    bottom.set_xlim(-2, 257)
    bottom.set_xlabel("Byte value of Ci xor Cj (all message pairs, overlapping bytes only)")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def plot_classes(rows, path):
    series = [("Reused key (measured)", BLUE, "reuse")]
    if any(r["predicted"] != "" for r in rows):
        series.append(("Reused key (predicted)", GREEN, "predicted"))
    series.append(("Independent keys (measured)", ORANGE, "control"))

    fig, ax = plt.subplots(figsize=(9, 4.6 if len(series) == 2 else 5.3))
    h = 0.72 / len(series)
    for i, (label, colour, column) in enumerate(series):
        shift = (i - (len(series) - 1) / 2) * (h + 0.03)
        for y, r in enumerate(rows):
            if r[column] == "":
                continue
            value = 100 * r[column]
            ax.barh(y + shift, value, height=h, color=colour, label=label if y == 0 else None)
            if column == "reuse":
                ax.text(value + 0.6, y + shift, f"{value:.1f}%", va="center", fontsize=9, color=GREY)

    # black tick on the control bar = share expected for uniform random bytes
    shift = ((len(series) - 1) / 2) * (h + 0.03)
    for y, r in enumerate(rows):
        u = 100 * r["uniform"]
        ax.plot([u, u], [y + shift - 0.7 * h, y + shift + 0.7 * h], color=DARK, linewidth=1.5,
                label="Uniform bytes (class width / 256)" if y == 0 else None)

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{r['byte_range']}\n{r['usual_cause']}" for r in rows])
    ax.invert_yaxis()
    ax.set_xlabel("Share of positions of Ci xor Cj (%)")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    ax.spines["bottom"].set_visible(False)
    # matplotlib lists the line first, move it after the bars
    handles, labels = ax.get_legend_handles_labels()
    handles.append(handles.pop(0))
    labels.append(labels.pop(0))
    ax.legend(handles, labels, loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2,
              frameon=False, labelcolor=GREY)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="OTP key reuse experiments")
    parser.add_argument("--fresh", action="store_true",
                        help="use new secure random keys and write to fresh_run/")
    args = parser.parse_args()

    if args.fresh:
        rng = None
        data_out = results = HERE / "fresh_run"
    else:
        rng = random.Random(SEED)
        data_out = DATA
        results = HERE / "results"
    results.mkdir(exist_ok=True)

    lines = []

    def out(text=""):
        print(text)
        lines.append(text)

    out("OTP key reuse experiments")
    if args.fresh:
        out("keys: new random keys from the OS (secrets)")
    else:
        out(f"keys: seeded generator, seed {SEED} (reproducible demo data, not secure)")

    # 1. corpus
    messages = load_corpus()
    total_chars = sum(len(p) for p in messages.values())
    mix = Counter(char_type(b) for p in messages.values() for b in p)
    out()
    out("[1] Corpus")
    out("    lengths: " + ", ".join(f"{mid}={len(p)}" for mid, p in messages.items()))
    out("    characters: " + ", ".join(f"{k} {100 * n / total_chars:.1f}%" for k, n in mix.most_common()))

    # 2. the pad manager refuses reuse unless the flag is set
    first, second = list(messages.values())[:2]
    pad = OneTimePad.generate(max(len(first), len(second)))
    pad.encrypt(first)
    out()
    out("[2] Pad manager")
    try:
        pad.encrypt(second, offset=0)
        raise SystemExit("pad manager did not refuse key reuse")
    except KeyReuseError as e:
        out(f"    second message at offset 0 with a normal pad -> KeyReuseError: {e}")
    out("    the reuse experiment has to set allow_reuse=True")

    # 3. encrypt and write the files, then read them back so the analysis
    #    uses exactly what the attack code will read
    reuse, control = make_sets(messages, rng)
    write_set(data_out / REUSE_FILE, "reuse", reuse)
    write_set(data_out / CONTROL_FILE, "control", control)
    sets = {
        "reuse": read_set(data_out / REUSE_FILE),
        "control": read_set(data_out / CONTROL_FILE),
    }
    out()
    out("[3] Ciphertexts written and checked against the data contract")
    out(f"    {data_out.name}/{REUSE_FILE}  (reuse)")
    out(f"    {data_out.name}/{CONTROL_FILE}  (control)")

    # 4. XOR identity
    identity = {name: identity_table(name, messages, cts) for name, cts in sets.items()}
    n_pairs = len(identity["reuse"])
    n_pos = sum(r["overlap"] for r in identity["reuse"])
    out()
    out(f"[4] Ci xor Cj = Pi xor Pj ?   ({n_pairs} pairs, {n_pos} overlapping positions)")
    for name, rows in identity.items():
        pairs_ok = sum(r["identity_holds"] for r in rows)
        equal = sum(r["equal_positions"] for r in rows)
        out(f"    {name:<8} holds for {pairs_ok:>2}/{n_pairs} pairs, {equal:>4}/{n_pos} positions")
    out(f"    positions equal just by chance would be about {n_pos / 256:.1f}")

    # 5. chi-square against uniform
    hist = {name: xor_histogram(list(cts.values())) for name, cts in sets.items()}
    chi = {name: chi_square(h) for name, h in hist.items()}
    trials = control_trials(messages, N_TRIALS, rng)
    out()
    out("[5] Chi-square of the bytes of Ci xor Cj against uniform (255 degrees of freedom)")
    out(f"    for uniform bytes we expect about 255 (standard deviation {math.sqrt(2 * 255):.1f})")
    out(f"    reuse    {chi['reuse']:>10.1f}")
    out(f"    control  {chi['control']:>10.1f}")
    out(f"    control repeated {N_TRIALS} times: mean {statistics.mean(trials):.1f}, "
        f"st. dev. {statistics.stdev(trials):.1f}, min {min(trials):.1f}, max {max(trials):.1f}")
    out(f"    repetitions that reached the reuse value: {sum(t >= chi['reuse'] for t in trials)}")

    # 6. share of positions in each class, next to the theory prediction if we have it
    predicted = {}
    if (DATA / "predictions.json").exists():
        with open(DATA / "predictions.json", encoding="utf-8") as f:
            predicted = json.load(f)
    class_rows = []
    for name, byte_range, cause, ranges in CLASSES:
        width = sum(high - low + 1 for low, high in ranges)
        class_rows.append({
            "class": name,
            "byte_range": byte_range,
            "usual_cause": cause,
            "reuse": class_count(hist["reuse"], ranges) / n_pos,
            "predicted": predicted.get(name, ""),
            "control": class_count(hist["control"], ranges) / n_pos,
            "uniform": width / 256,
        })
    out()
    out("[6] Share of positions in each class")
    out(f"    {'byte range':<17} {'usual cause':<31} {'reuse':>7} {'predicted':>10} {'control':>8} {'uniform':>8}")
    for r in class_rows:
        pred = "-" if r["predicted"] == "" else f"{100 * r['predicted']:.1f}%"
        out(f"    {r['byte_range']:<17} {r['usual_cause']:<31} {100 * r['reuse']:>6.1f}% {pred:>10} "
            f"{100 * r['control']:>7.1f}% {100 * r['uniform']:>7.1f}%")
    if not predicted:
        out("    (no data/predictions.json yet, so the predicted column is empty)")

    types = pair_types(messages)
    out()
    out("    what actually meets at each position (from the plaintexts):")
    for kind, n in types.most_common(6):
        out(f"      {kind:<26} {100 * n / n_pos:>5.1f}%")

    # 7. different lengths
    lengths = sorted(len(p) for p in messages.values())
    out()
    out("[7] Different lengths")
    out(f"    key bytes 0-{lengths[-2] - 1} were used by at least two messages")
    out(f"    key bytes {lengths[-2]}-{lengths[-1] - 1} were used only by the longest message, "
        f"so its last {lengths[-1] - lengths[-2]} characters are still safe")

    # tables and figures
    write_csv(results / "xor_identity.csv", identity["reuse"] + identity["control"])
    write_csv(results / "chi_square.csv", [
        {"what": "reuse", "chi_square": round(chi["reuse"], 2)},
        {"what": "control", "chi_square": round(chi["control"], 2)},
        {"what": f"control repeated {N_TRIALS} times, mean", "chi_square": round(statistics.mean(trials), 2)},
        {"what": f"control repeated {N_TRIALS} times, st. dev.", "chi_square": round(statistics.stdev(trials), 2)},
        {"what": f"control repeated {N_TRIALS} times, min", "chi_square": round(min(trials), 2)},
        {"what": f"control repeated {N_TRIALS} times, max", "chi_square": round(max(trials), 2)},
    ])
    write_csv(results / "xor_classes.csv", [
        {k: round(v, 4) if isinstance(v, float) else v for k, v in r.items()} for r in class_rows
    ])
    write_csv(results / "xor_histogram.csv", [
        {"byte": f"0x{v:02X}", "reuse": hist["reuse"][v], "control": hist["control"][v]}
        for v in range(256)
    ])
    write_csv(results / "pair_types.csv", [
        {"pair": kind, "positions": n, "share": round(n / n_pos, 4)} for kind, n in types.most_common()
    ])
    plot_histogram(hist["reuse"], hist["control"], chi["reuse"], chi["control"],
                   results / "fig_xor_histogram.png")
    plot_classes(class_rows, results / "fig_xor_classes.png")

    out()
    out(f"tables and figures are in {results.name}/")
    with open(results / "summary.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
