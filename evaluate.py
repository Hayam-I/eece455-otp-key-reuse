"""evaluate.py - measure the crib-dragging attack.

Ground truth (corpus) is used HERE ONLY, to score what the attack found.

Experiments (each run on the reused-key set AND the independent-key control)
  E1  top-1 / top-3 success of the correct crib offset vs crib length (3-12)
      and crib type (common vs rare)                      [message pairs]
  E2  top-1 / top-3 success vs number of ciphertexts      [cross-checking]
  E3  iterative recovery: fraction of overlap recovered per round, vs number
      of ciphertexts, plus an ablation of the recovery components
Chance level for E1/E2 is the average of k / (number of candidate offsets).

Trials vary message pairs and crib positions, NOT keys: the attack works on
C1 xor C2 = P1 xor P2, which does not depend on the key value.  (Trials are
not independent - they share six messages - so differences of a few percent
are within noise.)

Usage:  python evaluate.py            # uses config.DATA_MODE (dummy by default)
        python evaluate.py --quick    # fast smoke run
Outputs go to results/<mode>/ : CSV tables, summary.md, figures, captions.md,
walkthrough.txt.  Dummy runs are stamped "DUMMY DATA" on every figure.
"""
import argparse
import csv
import itertools
import random
import time

import numpy as np
import matplotlib
import matplotlib.ticker
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import config
import crib_drag as cd

# ----------------------------------------------------------------- helpers
COMMON_FRAGMENTS = ("the", "and", "that", "with", "for", "from", "have", "this",
                    "are", "was", "were", "not", "but", "will", "been", "they",
                    "their", "which", "would", "there", "ing ", "tion", "ment")


def crib_type(crib: bytes) -> str:
    """'common' if the crib contains a frequent English word/ending, else 'rare'."""
    c = crib.decode("latin-1").lower()
    return "common" if any(f in c for f in COMMON_FRAGMENTS) else "rare"


def mean(xs):
    return float(np.mean(xs)) if len(xs) else float("nan")


def metrics(cts, plains, key):
    """Score a recovered key against ground truth over the overlap region
    (positions covered by >= 2 of the given ciphertexts)."""
    ids = list(cts)
    lens = {i: len(cts[i]) for i in ids}
    corr = wrong = total = complete = 0
    for i in ids:
        all_ok = True
        for p in range(lens[i]):
            if sum(1 for j in ids if lens[j] > p) < 2:
                continue
            total += 1
            if key[p] >= 0 and (cts[i][p] ^ int(key[p])) == plains[i][p]:
                corr += 1
            else:
                all_ok = False
                wrong += key[p] >= 0
        complete += all_ok
    return {"correct": corr, "wrong": int(wrong), "total": total,
            "frac_correct": corr / total,
            "precision": corr / (corr + wrong) if corr + wrong else float("nan"),
            "complete_messages": complete}


# ------------------------------------------------------------- E1: crib length
def exp_length(cts, plains, lengths, stride):
    ids = list(cts)
    arrs = [np.frombuffer(cts[i], np.uint8) for i in ids]
    rows = []
    for L in lengths:
        acc = {"all": [], "common": [], "rare": []}
        for ia, a in enumerate(ids):
            for ib, b in enumerate(ids):
                if a == b:
                    continue
                overlap = min(len(plains[a]), len(plains[b]))
                for o in range(0, overlap - L + 1, stride):
                    crib = plains[a][o:o + L]
                    score, valid = cd.rank_crib(arrs, ia, np.frombuffer(crib, np.uint8), [ib])
                    p, ch, _ = cd.rank_stats(score, valid, o)
                    rec = (p[1], p[3], ch[1], ch[3])
                    acc["all"].append(rec)
                    acc[crib_type(crib)].append(rec)
        for t, recs in acc.items():
            if recs:
                r = np.array(recs)
                rows.append({"crib_len": L, "crib_type": t, "trials": len(recs),
                             "top1": r[:, 0].mean(), "top3": r[:, 1].mean(),
                             "chance_top1": r[:, 2].mean(), "chance_top3": r[:, 3].mean()})
    return rows


# --------------------------------------------------------------- E2: #ciphertexts
def exp_ncts(cts, plains, L, stride, rng):
    ids = list(cts)
    arrs = [np.frombuffer(cts[i], np.uint8) for i in ids]
    rows = []
    for N in range(2, len(ids) + 1):
        recs = []
        for ia, a in enumerate(ids):
            others = rng.sample([j for j in range(len(ids)) if j != ia], N - 1)
            for o in range(0, len(plains[a]) - L + 1, stride):
                crib = plains[a][o:o + L]
                score, valid = cd.rank_crib(arrs, ia, np.frombuffer(crib, np.uint8), others)
                if not valid[o]:
                    continue
                p, ch, _ = cd.rank_stats(score, valid, o)
                recs.append((p[1], p[3], ch[1], ch[3]))
        r = np.array(recs)
        rows.append({"n_ciphertexts": N, "crib_len": L, "trials": len(recs),
                     "top1": r[:, 0].mean(), "top3": r[:, 1].mean(),
                     "chance_top1": r[:, 2].mean(), "chance_top3": r[:, 3].mean()})
    return rows


# ------------------------------------------------------------ E3: recovery
def exp_recovery(cts, plains, reps, rng, **kw):
    """Run iterative recovery for N = 2..all ciphertexts (random subsets)."""
    ids = list(cts)
    rows, curves = [], {}
    for N in range(2, len(ids) + 1):
        combos = list(itertools.combinations(ids, N))
        chosen = combos if len(combos) <= reps else rng.sample(combos, reps)
        ms, cl = [], []
        for sub in chosen:
            sub_cts = {i: cts[i] for i in sub}
            res = cd.recover(sub_cts, **kw)
            ms.append({**metrics(sub_cts, plains, res.key), "rounds": len(res.history) - 1})
            cl.append([metrics(sub_cts, plains, h["key"])["frac_correct"] for h in res.history])
        width = max(len(c) for c in cl)
        curves[N] = np.mean([c + [c[-1]] * (width - len(c)) for c in cl], axis=0)
        rows.append({"n_ciphertexts": N, "runs": len(chosen),
                     **{k: mean([m[k] for m in ms]) for k in
                        ("correct", "wrong", "total", "frac_correct", "precision",
                         "complete_messages", "rounds")}})
    return rows, curves


def assisted_completion(cts, plains, key):
    """Simulate the analyst-in-the-loop step of the attack.

    After the automatic phase the analyst reads the partially decrypted text,
    spots each word that still has an unknown or wrong character (e.g.
    'no_t_hern'), and supplies the whole word as a confirmed fragment.  Each
    supplied word fixes the key bytes under it for ALL ciphertexts.  Messages
    are worked shortest first.  Ground truth is used here only to stand in for
    the analyst's reading, and the number of word guesses is reported as the
    human effort needed.  Returns (key, seeds, cumulative_seed_counts)."""
    ids = sorted(cts, key=lambda i: len(cts[i]))
    key = key.copy()
    lens = {i: len(cts[i]) for i in ids}
    seeds, cum = [], []
    alnum = lambda b: chr(b).isalnum()

    def covered_bad(i, p):
        covered = sum(1 for j in ids if lens[j] > p) >= 2
        return covered and not (key[p] >= 0 and (cts[i][p] ^ int(key[p])) == plains[i][p])

    for i in ids:
        text, p = plains[i], 0
        while p < len(text):
            if not covered_bad(i, p):
                p += 1
                continue
            s, e = p, p + 1
            if alnum(text[p]):                          # a word: supply all of it
                while s > 0 and alnum(text[s - 1]):
                    s -= 1
                while e < len(text) and alnum(text[e]):
                    e += 1
            else:                                       # punctuation/space: just that character
                while e < len(text) and not alnum(text[e]) and covered_bad(i, e):
                    e += 1
            for q in range(s, e):                       # the analyst's word fixes the key
                key[q] = cts[i][q] ^ text[q]
            seeds.append((i, s, text[s:e].decode()))
            p = e
        cum.append((i, len(seeds)))
    return key, seeds, cum


def exp_ablation(cts, plains):
    variants = {
        "full (cribs + commit filter + extension)": {},
        "no extension": {"extend": False},
        "no commit filter": {"commit_margin": 0.0},
        "+ space heuristic": {"use_space": True},
        "+ joint gap search (tried, off by default)": {"gap_fill": True},
    }
    rows = []
    for name, kw in variants.items():
        res = cd.recover(cts, **kw)
        rows.append({"variant": name, **metrics(cts, plains, res.key),
                     "rounds": len(res.history) - 1})
    return rows


# ----------------------------------------------------------------- output
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"


def _style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(AXIS)
    ax.grid(axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.xaxis.label.set_color(INK2)
    ax.yaxis.label.set_color(INK2)
    ax.title.set_color(INK)


def _line(ax, x, y, color, label, ls="-", marker="o"):
    ax.plot(x, y, color=color, lw=2, ls=ls, marker=marker, markersize=6,
            markeredgecolor=SURFACE, markeredgewidth=1.2, label=label)


def _finish(fig, axes, path, tag, handles_from, ncol=None, bottom=0.09):
    h, l = handles_from.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=ncol or len(l), frameon=False, fontsize=9,
               labelcolor=INK2)
    fig.suptitle(tag, color=INK, fontsize=10, x=0.01, ha="left")
    fig.tight_layout(rect=(0, bottom, 1, 0.95))
    fig.savefig(path, dpi=160, facecolor=SURFACE)
    plt.close(fig)


def md_table(rows, cols, fmt=None):
    fmt = fmt or {}
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        cells = []
        for c in cols:
            v = r[c]
            if isinstance(v, (float, np.floating)):
                f = fmt.get(c) or ("{:.0f}" if abs(v) >= 100 else "{:.3g}")
                cells.append(f.format(v))
            else:
                cells.append(str(v))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def walkthrough(path, ids, cts, history, tag):
    picks = sorted({0, 1, 2, 3, len(history) // 2, len(history) - 1} & set(range(len(history))))
    lines = [tag, "Step-by-step recovery on the reused-key set (ciphertexts only; '_' = unknown)", ""]
    for n in picks:
        h = history[n]
        lines.append(f"--- round {n}: {h['action'][:300]}")
        lines.append(f"    known key bytes: {int((h['key'] >= 0).sum())}/{len(h['key'])}")
        for i in ids:
            lines.append(f"    {i}: {cd.decrypt_partial(cts[i], h['key']).decode('latin-1')}")
        lines.append("")
    path.write_text("\n".join(lines))


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stride", type=int, default=3, help="crib position stride (trial subsampling)")
    ap.add_argument("--reps", type=int, default=3, help="random subsets per N in E3")
    ap.add_argument("--lengths", default="3-12")
    ap.add_argument("--n-len", type=int, default=6, help="crib length used in E2")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.stride, args.reps = 9, 1
    lo, hi = (int(x) for x in args.lengths.split("-"))
    lengths = list(range(lo, hi + 1))

    mode = config.DATA_MODE
    P = config.PATHS[mode]
    out = config.RESULTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    tag = ("DUMMY DATA - not for the report" if mode == "dummy"
           else f"Data: {mode} (ciphertexts.json from C)")
    print(f"== evaluate.py [{mode}] -> {out}")

    sets = {s: cd.load_set(P[s], s) for s in ("reuse", "control")}
    plains = cd.load_corpus(P["corpus"])
    ids = list(sets["reuse"])
    assert list(sets["control"]) == ids and all(i in plains for i in ids), "id mismatch"
    for s in sets.values():
        for i in ids:
            assert len(s[i]) == len(plains[i]), f"length mismatch for {i}"
    rng = random.Random(config.SEED)
    t0 = time.time()

    def lap(msg):
        print(f"  [{time.time() - t0:5.1f}s] {msg}", flush=True)

    # E1, E2
    e1 = {s: exp_length(sets[s], plains, lengths, args.stride) for s in sets}
    lap("E1 crib length done")
    e2 = {s: exp_ncts(sets[s], plains, args.n_len, args.stride, rng) for s in sets}
    lap("E2 number of ciphertexts done")
    for s in sets:
        write_csv(out / f"e1_crib_length_{s}.csv", e1[s])
        write_csv(out / f"e2_num_ciphertexts_{s}.csv", e2[s])

    # E3
    e3, curves = {}, {}
    e3["reuse"], curves["reuse"] = exp_recovery(sets["reuse"], plains, args.reps, rng)
    lap("E3 recovery (reuse) done")
    e3["control"], curves["control"] = exp_recovery(sets["control"], plains, 1, rng)
    lap("E3 recovery (control) done")
    abl = exp_ablation(sets["reuse"], plains)
    lap("ablation done")
    for s in sets:
        write_csv(out / f"e3_recovery_{s}.csv", e3[s])
    write_csv(out / "e3_ablation.csv", abl)

    full = cd.recover(sets["reuse"])
    full_m = metrics(sets["reuse"], plains, full.key)
    akey, seeds, cum = assisted_completion(sets["reuse"], plains, full.key)
    asst_m = metrics(sets["reuse"], plains, akey)
    walkthrough(out / "walkthrough.txt", ids, sets["reuse"], full.history, tag)
    with open(out / "walkthrough.txt", "a") as f:
        f.write("--- analyst-assisted completion (words supplied after reading the partial text)\n")
        f.write("    " + ", ".join(f"{m}@{o}:{w!r}" for m, o, w in seeds) + "\n")
        for i in ids:
            f.write(f"    {i}: {cd.decrypt_partial(sets['reuse'][i], akey).decode('latin-1')}\n")

    # ------------------------------------------------------------ figures
    def rows_of(rows, t):
        return [r for r in rows if r["crib_type"] == t]

    fig, axes = plt.subplots(1, 2, figsize=(9.5, 4), sharey=True, facecolor=SURFACE)
    for ax, k in zip(axes, ("top1", "top3")):
        for rows, t, color, lab, ls in (
                (e1["reuse"], "common", BLUE, "reused key, common cribs", "-"),
                (e1["reuse"], "rare", ORANGE, "reused key, rare cribs", "-"),
                (e1["control"], "all", AQUA, "independent keys (control)", "-")):
            rr = rows_of(rows, t)
            if rr:
                _line(ax, [r["crib_len"] for r in rr], [r[k] for r in rr], color, lab, ls)
        ra = rows_of(e1["reuse"], "all")
        _line(ax, [r["crib_len"] for r in ra], [r["chance_" + k] for r in ra], MUTED,
              "chance level", "--", marker="")
        _style(ax)
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("crib length (characters)")
        ax.set_title("Top-1 success" if k == "top1" else "Top-3 success", fontsize=10, loc="left")
    axes[0].set_ylabel("P(correct offset ranked in top-k)")
    _finish(fig, axes, out / "fig1_success_vs_crib_length.png", tag, axes[0])

    fig, axes = plt.subplots(1, 2, figsize=(9.5, 4), sharey=True, facecolor=SURFACE)
    for ax, k in zip(axes, ("top1", "top3")):
        _line(ax, [r["n_ciphertexts"] for r in e2["reuse"]], [r[k] for r in e2["reuse"]],
              BLUE, "reused key")
        _line(ax, [r["n_ciphertexts"] for r in e2["control"]], [r[k] for r in e2["control"]],
              AQUA, "independent keys (control)")
        _line(ax, [r["n_ciphertexts"] for r in e2["reuse"]], [r["chance_" + k] for r in e2["reuse"]],
              MUTED, "chance level", "--", marker="")
        _style(ax)
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("number of ciphertexts cross-checked")
        ax.set_xticks([r["n_ciphertexts"] for r in e2["reuse"]])
        ax.set_title("Top-1 success" if k == "top1" else "Top-3 success", fontsize=10, loc="left")
    axes[0].set_ylabel("P(correct offset ranked in top-k)")
    _finish(fig, axes, out / "fig2_success_vs_num_ciphertexts.png", tag, axes[0])

    fig, ax = plt.subplots(figsize=(8, 4), facecolor=SURFACE)
    nmax = max(curves["reuse"])
    for N, color in zip(sorted({2, 3, 4, nmax}), (BLUE, ORANGE, AQUA, YELLOW)):
        c = curves["reuse"][N]
        _line(ax, range(len(c)), c, color, f"reused key, {N} ciphertexts" + (" (all)" if N == nmax else ""), marker="o")
    c = curves["control"][nmax]
    _line(ax, range(len(c)), c, MUTED, f"independent keys, {nmax} ciphertexts", "--", marker="")
    _style(ax)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("recovery round (0 = nothing known)")
    ax.set_ylabel("fraction of overlap correctly recovered")
    ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    _finish(fig, [ax], out / "fig3_recovery_per_round.png", tag, ax, ncol=3, bottom=0.17)

    (out / "captions.md").write_text(
        f"{tag}\n\n"
        "Figure 1. Top-1 (left) and top-3 (right) success of ranking the correct crib offset in a "
        "message pair, versus crib length, for common and rare cribs under a reused key and for the "
        "independent-key control. The dashed line is chance (k divided by the number of candidate offsets).\n\n"
        f"Figure 2. Top-1 and top-3 success versus the number of ciphertexts used to cross-check a "
        f"{args.n_len}-character crib. Reused key rises with more ciphertexts; the control stays at chance.\n\n"
        "Figure 3. Fraction of the overlap region (positions covered by at least two ciphertexts) that is "
        "decrypted correctly after each recovery round, for 2, 3, 4 and all ciphertexts under a reused key, "
        "and for the independent-key control.\n")

    # ------------------------------------------------------------ summary
    s = [f"# Member D results ({mode})", "", tag, "",
         f"Trial subsampling stride {args.stride}; seed {config.SEED}. Trials vary message pairs and "
         "crib positions, not keys.", ""]
    for name in ("reuse", "control"):
        s += [f"## E1 - success vs crib length and type ({name})", "",
              md_table(e1[name], ["crib_len", "crib_type", "trials", "top1", "top3", "chance_top1", "chance_top3"]), ""]
    for name in ("reuse", "control"):
        s += [f"## E2 - success vs number of ciphertexts, {args.n_len}-char cribs ({name})", "",
              md_table(e2[name], ["n_ciphertexts", "trials", "top1", "top3", "chance_top1", "chance_top3"]), ""]
    cols = ["n_ciphertexts", "runs", "correct", "wrong", "total", "frac_correct", "precision",
            "complete_messages", "rounds"]
    for name in ("reuse", "control"):
        s += [f"## E3 - iterative recovery vs number of ciphertexts ({name})", "", md_table(e3[name], cols), ""]
    s += ["## Ablation (reused key, all ciphertexts)", "",
          md_table(abl, ["variant", "correct", "wrong", "total", "frac_correct", "precision",
                         "complete_messages", "rounds"]), ""]
    ok = full_m["complete_messages"] >= 2
    ok2 = asst_m["complete_messages"] >= 2
    s += ["## Definition-of-done check", "",
          f"- Fully automatic: messages recovered completely over the overlap region: "
          f"{full_m['complete_messages']} of {len(ids)} -> {'meets' if ok else 'DOES NOT meet'} the 'at least two' target.",
          f"- Overlap characters correct (automatic): {full_m['correct']}/{full_m['total']} "
          f"({100 * full_m['frac_correct']:.1f}%), wrong: {full_m['wrong']}.",
          f"- With analyst-supplied words after reading the partial text: "
          f"{asst_m['complete_messages']} of {len(ids)} complete -> {'meets' if ok2 else 'DOES NOT meet'} the target; "
          f"{len(seeds)} analyst guesses in total ({sum(any(c.isalnum() for c in w) for _, _, w in seeds)} words, "
          f"{sum(not any(c.isalnum() for c in w) for _, _, w in seeds)} single punctuation/space characters); "
          f"cumulative guesses, shortest message first: "
          + ", ".join(f"{m}: {c}" for m, c in cum) + ". "
          f"Words supplied: " + ", ".join(f"{m}@{o} {w!r}" for m, o, w in seeds) + ".",
          f"- Control (independent keys, all ciphertexts): {e3['control'][-1]['correct']:.0f} correct, "
          f"{e3['control'][-1]['wrong']:.0f} wrong of {e3['control'][-1]['total']:.0f}.", ""]
    (out / "summary.md").write_text("\n".join(s))
    lap(f"wrote {out}")
    print(f"complete messages (reuse, all): {full_m['complete_messages']}/{len(ids)}; "
          f"{full_m['correct']}/{full_m['total']} correct, {full_m['wrong']} wrong")


if __name__ == "__main__":
    main()
