"""crib_drag.py - crib-dragging attack on a reused one-time-pad key.

The attack reads CIPHERTEXTS ONLY.  Plaintext is used solely in evaluate.py
for scoring.  Messages are aligned at byte 0; only overlapping length counts.

Core identity:  C1 xor C2 = P1 xor P2   (the key cancels).
Dragging:       a guessed crib c placed in message a at offset o gives the
                candidate  P_b[o:o+L] = (C_a xor C_b)[o:o+L] xor c
                for every other message b.  The correct offset is the one
                where the candidates look like English.
Recovery:       an accepted fragment gives key bytes K[i] = C_a[i] xor P_a[i];
                these decrypt every other ciphertext at the same positions,
                the known region is extended left/right, and every step is
                cross-checked against all ciphertexts that cover it.

CLI examples
    python crib_drag.py rank    --set reuse --a m1 --crib " the " --top 5
    python crib_drag.py recover --set reuse
    python crib_drag.py recover --set reuse --seed m1:0:"The "
"""
import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view as swv

import config
import scoring as S

# ----------------------------------------------------------------- data I/O
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR truncated to the shorter input (the overlap)."""
    return bytes(x ^ y for x, y in zip(a, b))


def load_set(path, expected_set=None) -> dict:
    """Load a ciphertext set in the agreed data contract -> {id: bytes}.

    Contract: {"set": "reuse"|"control",
               "messages": [{"id": "m1", "ciphertext_hex": "..."}, ...]}
    Hex strings only; no plaintext and no key (checked here).
    """
    obj = json.loads(Path(path).read_text())
    if isinstance(obj, list):                       # list of sets in one file
        obj = next(o for o in obj if expected_set in (None, o.get("set")))
    elif "set" not in obj and expected_set in obj:  # {"reuse": {...}, ...}
        obj = obj[expected_set]
    if expected_set and obj.get("set") != expected_set:
        raise ValueError(f"{path}: expected set '{expected_set}', got '{obj.get('set')}'")
    out = {}
    for m in obj["messages"]:
        if set(m) - {"id", "ciphertext_hex"}:
            raise ValueError(f"{path}: contract allows only id and ciphertext_hex, got {sorted(m)}")
        out[m["id"]] = bytes.fromhex(m["ciphertext_hex"])
    if len(out) < 2:
        raise ValueError(f"{path}: need at least two messages")
    return out


def load_corpus(path) -> dict:
    """Ground-truth plaintexts -> {id: bytes}.  Used by evaluate.py ONLY.

    Accepts {"messages": [{"id", "plaintext"}]}, a bare list of those, or
    {id: text}.  Adjust here if corpus.json uses other field names.
    """
    obj = json.loads(Path(path).read_text())
    if isinstance(obj, dict) and "messages" in obj:
        obj = obj["messages"]
    if isinstance(obj, list):
        out = {}
        for m in obj:
            text = next(m[k] for k in ("plaintext", "text", "message") if k in m)
            out[m["id"]] = text.encode("ascii")
        return out
    return {k: v.encode("ascii") for k, v in obj.items()}


# ------------------------------------------------------------- crib library
_WORDS = ("the and that with from this have will they were been which would "
          "there their about should could before after not are was has had "
          "all but you our his her must than when what into more only for "
          "can may your these those other some such each any").split()
_PHRASES = ["of the", "in the", "to the", "on the", "at the", "for the",
            "is the", "and the", "by the", "of our", "to be", "in a"]
_ENDINGS = ["ing ", "tion ", "ment ", "ould ", "ight ", "ther", "ation", "ever"]


START_ONLY = set()   # cribs without a leading space: tried only at offset 0


def build_crib_list(case_variants=("lower", "capital")) -> list:
    """Common-word cribs (length >= 4), with spaces at the boundaries.

    Add "upper" to case_variants for telegram-style all-capital messages."""
    base = []
    for w in _WORDS + _PHRASES:
        base += [(f" {w} ", False), (f"{w} ", True)]   # mid-message / message start
    base += [(e, False) for e in _ENDINGS]
    out = []
    for c, start_only in base:
        if len(c) < 4:
            continue
        variants = {"lower": c.lower(), "upper": c.upper()}
        i = next((k for k, ch in enumerate(c) if ch.isalpha()), None)
        if i is not None:
            variants["capital"] = c[:i] + c[i].upper() + c[i + 1:]
        for name in case_variants:
            if name in variants:
                b = variants[name].encode("ascii")
                out.append(b)
                if start_only:
                    START_ONLY.add(b)
    return sorted(set(out))


DEFAULT_CRIBS = build_crib_list()


# ------------------------------------------------------- crib dragging core
def rank_crib(arrs, a, crib, others=None):
    """Drag `crib` (assumed to be inside message a) over every offset.

    arrs : list of uint8 arrays (ciphertexts)       crib : uint8 array
    others : indices of the other ciphertexts used for cross-checking
             (default: all).  With two ciphertexts this is the classic pair attack.
    Returns (score, valid): score[o] is the mean combined English score of the
    implied fragments of the other messages at offset o; valid[o] says that at
    least one other message covers offset o.
    """
    ca, L = arrs[a], len(crib)
    n_off = len(ca) - L + 1
    if n_off <= 0:
        return np.zeros(0), np.zeros(0, bool)
    if others is None:
        others = [j for j in range(len(arrs)) if j != a]
    implied_key = swv(ca, L) ^ crib                       # (n_off, L)
    tot, cnt = np.zeros(n_off), np.zeros(n_off)
    for j in others:
        cj = arrs[j]
        if len(cj) < L:
            continue
        wj = swv(cj, L)
        r = min(n_off, len(wj))
        tot[:r] += S.combined_score(wj[:r] ^ implied_key[:r])
        cnt[:r] += 1
    valid = cnt > 0
    score = np.full(n_off, -np.inf)
    score[valid] = tot[valid] / cnt[valid]
    return score, valid


def drag(ca: bytes, cb: bytes, crib: bytes, top=None):
    """Pair attack: crib is in message a; candidates are fragments of b.
    Returns [(offset, fragment_bytes, score)] best first."""
    arrs = [np.frombuffer(ca, np.uint8), np.frombuffer(cb, np.uint8)]
    cr = np.frombuffer(crib, np.uint8)
    score, valid = rank_crib(arrs, 0, cr)
    D = xor_bytes(ca, cb)
    offs = [o for o in np.argsort(-score) if valid[o]]
    res = [(int(o), xor_bytes(D[o:o + len(crib)], crib), float(score[o])) for o in offs]
    return res if top is None else res[:top]


def fragment_at(ca: bytes, cb: bytes, crib: bytes, offset: int) -> bytes:
    """Candidate fragment of message b if the crib sits at `offset` of a."""
    D = xor_bytes(ca, cb)
    return xor_bytes(D[offset:offset + len(crib)], crib)


def rank_stats(score, valid, correct_offset, k_values=(1, 3)):
    """Success probability of the correct offset being in the top-k.

    Ties are resolved in expectation (the correct offset sits uniformly among
    equal scores), so the control run is not distorted by arbitrary ordering.
    Returns ({k: p_topk}, {k: chance_topk}, n_valid)."""
    s = score[valid]
    c = score[correct_offset]
    n = int(valid.sum())
    greater = int((s > c + 1e-9).sum())
    equal = int((np.abs(s - c) <= 1e-9).sum()) - 1
    p = {k: float(np.clip((k - greater) / (equal + 1), 0.0, 1.0)) for k in k_values}
    chance = {k: min(k, n) / n for k in k_values}
    return p, chance, n


# --------------------------------------------------------- iterative recovery
NULL_MEAN = -4.5   # approx. mean score of random printable text (evidence baseline)


def _best_word_candidate(arrs, key, cribs, min_cover, min_mean, ev_thr, banned=(),
                         max_cands=25):
    """Ranked list of (evidence, message, offset, key_bytes, crib) placements
    whose implied fragments in all covering other messages are printable and
    English-like, and consistent with the key bytes already known."""
    n = len(arrs)
    cands = []
    for m in range(n):
        cm = arrs[m]
        for w in cribs:
            k = len(w)
            if len(cm) < k:
                continue
            kc = swv(cm, k) ^ np.frombuffer(w, np.uint8)          # implied key (O,k)
            O = len(kc)
            kk = swv(key, k)[:O]
            known = kk >= 0
            ok = np.all(~known | (kk == kc.astype(np.int16)), axis=1) & (~known).any(axis=1)
            rows = np.nonzero(ok)[0]
            if w in START_ONLY:
                rows = rows[rows == 0]
            if banned:
                rows = np.array([r for r in rows if (m, int(r), w) not in banned], dtype=rows.dtype)
            if rows.size == 0:
                continue
            tot, cnt = np.zeros(O), np.zeros(O)
            for j in range(n):
                if j == m or rows.size == 0 or len(arrs[j]) < k:
                    continue
                wj = swv(arrs[j], k)
                cov = rows[rows < len(wj)]
                if cov.size == 0:
                    continue
                frag = wj[cov] ^ kc[cov]
                good = S.PRINTABLE[frag].all(axis=1)
                if not good.all():
                    rows = np.setdiff1d(rows, cov[~good])
                tot[cov[good]] += S.combined_score(frag[good])
                cnt[cov[good]] += 1
            rows = rows[cnt[rows] >= min_cover]
            if rows.size == 0:
                continue
            mean = tot[rows] / cnt[rows]
            evidence = (mean - NULL_MEAN) * k * cnt[rows]
            good = (mean >= min_mean) & (evidence >= ev_thr)
            for i in np.nonzero(good)[0]:
                o = int(rows[i])
                cands.append((float(evidence[i]), m, o, kc[o].copy(), w))
    cands.sort(key=lambda c: -c[0])
    return cands[:max_cands]


_KCANDS = np.arange(256, dtype=np.uint8)


def _column_scores(arrs, key, p, cov=None):
    """Score all 256 possible key bytes at position p.

    Each candidate k decrypts every ciphertext covering p; the implied
    characters are scored with the unigram model, or with the bigram model
    against already-known left/right neighbours (from `key`).
    Returns (scores[256], plain[256, c])."""
    n, L = len(arrs), len(key)
    if cov is None:
        cov = [j for j in range(n) if len(arrs[j]) > p]
    cv = np.array([arrs[j][p] for j in cov], dtype=np.uint8)
    plain = cv[None, :] ^ _KCANDS[:, None]                        # (256, c)
    # Message-initial capitals: the model is biased toward lower case, so at
    # position 0 case is folded and upper/lower key candidates tie (left open).
    plain_s = np.where(S.IS_UPPER[plain], plain | 0x20, plain).astype(np.uint8) if p == 0 else plain
    sc = np.zeros(256)
    for idx, j in enumerate(cov):
        pc = plain_s[:, idx]
        if p > 0 and key[p - 1] >= 0:
            sc += S.BI[arrs[j][p - 1] ^ np.uint8(key[p - 1]), pc]
        else:
            sc += S.UNI[pc]
        if p + 1 < L and key[p + 1] >= 0 and len(arrs[j]) > p + 1:
            sc += S.BI[pc, arrs[j][p + 1] ^ np.uint8(key[p + 1])]
    return sc, plain


def _commit_confident(arrs, key, o, kb, commit_margin):
    """Commit the key bytes of an accepted crib placement position by position,
    but only where that byte is clearly the best explanation of the whole
    column (all ciphertexts covering it).  Edge characters of a crib, which
    carry the least evidence, are the usual casualties."""
    tentative = key.copy()
    tentative[o:o + len(kb)] = kb
    committed = 0
    for j, p in enumerate(range(o, o + len(kb))):
        if key[p] >= 0:
            continue
        cov = [i for i in range(len(arrs)) if len(arrs[i]) > p]
        if len(cov) < 2:
            continue
        sc, plain = _column_scores(arrs, tentative, p, cov)
        order = np.argsort(-sc)
        if (order[0] == kb[j] and sc[order[0]] - sc[order[1]] >= commit_margin
                and S.PRINTABLE[plain[order[0]]].all()):
            key[p] = kb[j]
            committed += 1
    return committed


def _extend_edges(arrs, key, min_cover, margin, max_steps=5000):
    """Grow the known key region left and right, one position at a time.

    A frontier position p takes the key byte whose implied column (all
    ciphertexts covering p) scores best under the unigram/bigram model, using
    known neighbours as context.  Accepted only if every implied character is
    printable and the best byte beats the runner-up by `margin` nats
    (cross-check across >= min_cover + 1 ciphertexts)."""
    n, added = len(arrs), 0
    while True:
        known = key >= 0
        frontier = np.nonzero(~known & (np.r_[False, known[:-1]] | np.r_[known[1:], False]))[0]
        accepted = 0
        for p in frontier:
            if key[p] >= 0:
                continue
            cov = [j for j in range(n) if len(arrs[j]) > p]
            if len(cov) < min_cover + 1:
                continue
            sc, plain = _column_scores(arrs, key, p, cov)
            order = np.argsort(-sc)
            b, s2 = order[0], order[1]
            if sc[b] - sc[s2] >= margin and S.PRINTABLE[plain[b]].all():
                key[p] = b
                accepted += 1
        added += accepted
        if accepted == 0 or added >= max_steps:
            return added


def _fill_gaps(arrs, key, min_cover, gap_margin=4.0, max_gap=12, beam=64):
    """Fill short runs of unknown key bytes by a joint (beam) search.

    The single-position extension step needs each byte to win by a margin on
    its own, which fails inside a run of unknown bytes because only one
    neighbour is known.  Here the whole run is decoded together: a path is a
    choice of one key byte per position, scored by the bigram model on every
    ciphertext covering the position, with the known text on both sides of
    the run as context.  A path must decrypt to printable text in all
    covering ciphertexts.  The best path is committed only if it beats the
    best different path by `gap_margin` nats in total.  Returns bytes filled."""
    n, L, filled, p = len(arrs), len(key), 0, 0
    while p < L:
        if key[p] >= 0:
            p += 1
            continue
        s = p
        while p < L and key[p] < 0:
            p += 1
        e = p
        if e - s > max_gap:
            continue
        cov = [[j for j in range(n) if len(arrs[j]) > q] for q in range(s, e)]
        if any(len(c) < min_cover + 1 for c in cov):
            continue
        left = int(key[s - 1]) if s > 0 and key[s - 1] >= 0 else None
        beams = [(0.0, ())]
        for idx, q in enumerate(range(s, e)):
            cv = np.array([arrs[j][q] for j in cov[idx]], dtype=np.uint8)
            plain = cv[None, :] ^ _KCANDS[:, None]                      # (256, c)
            ok = S.PRINTABLE[plain].all(axis=1)
            if not ok.any():
                beams = []
                break
            new = []
            for score, path in beams:
                prev = path[-1] if path else left
                sc = np.zeros(256)
                for c_idx, j in enumerate(cov[idx]):
                    if prev is not None and q > 0:
                        sc += S.BI[arrs[j][q - 1] ^ np.uint8(prev), plain[:, c_idx]]
                    else:
                        sc += S.UNI[plain[:, c_idx]]
                for kb in np.nonzero(ok)[0]:
                    new.append((score + sc[kb], path + (int(kb),)))
            new.sort(key=lambda t: -t[0])
            beams = new[:beam]
        if len(beams) < 2:
            continue
        if e < L and key[e] >= 0:                                       # right-hand context
            rescored = []
            for score, path in beams:
                for j in range(n):
                    if len(arrs[j]) > e:
                        score += S.BI[arrs[j][e - 1] ^ np.uint8(path[-1]),
                                      arrs[j][e] ^ np.uint8(key[e])]
                rescored.append((score, path))
            beams = sorted(rescored, key=lambda t: -t[0])
        if beams[0][0] - beams[1][0] >= gap_margin:
            key[s:e] = beams[0][1]
            filled += e - s
    return filled


@dataclass
class RecoveryResult:
    ids: list
    lengths: list
    history: list = field(default_factory=list)   # [{"action", "key"}] per iteration

    @property
    def key(self):
        return self.history[-1]["key"]


def decrypt_partial(ct: bytes, key, unknown=b"_") -> bytes:
    """Decrypt with a partially known key; unknown positions shown as '_'."""
    return bytes((c ^ int(k)) if k >= 0 else unknown[0] for c, k in zip(ct, key))


def recover(cts: dict, seeds=(), cribs=None, min_cover=2, min_mean=-3.6,
            ev_thr=12.0, margin=4.0, commit_margin=1.5, max_per_round=6,
            max_iter=100, use_space=False, extend=True, gap_fill=False,
            gap_margin=4.0):
    """Iterative key recovery from ciphertexts only.

    cts   : {id: ciphertext bytes}
    seeds : [(id, offset, crib_bytes)] - optional human-confirmed fragments
    Each iteration: (1) accept the single best common-word crib placement
    that is consistent with the known key and English-like in all covering
    ciphertexts, (2) extend the known key left/right.  The key array after
    every iteration is stored in result.history.
    """
    ids = list(cts)
    arrs = [np.frombuffer(cts[i], np.uint8) for i in ids]
    cribs = DEFAULT_CRIBS if cribs is None else cribs
    min_cover = max(1, min(min_cover, len(ids) - 1))
    key = np.full(max(len(a) for a in arrs), -1, np.int16)
    res = RecoveryResult(ids, [len(a) for a in arrs])

    def snap(action):
        res.history.append({"action": action, "key": key.copy()})

    for mid, off, crib in seeds:
        m = ids.index(mid)
        key[off:off + len(crib)] = arrs[m][off:off + len(crib)] ^ np.frombuffer(crib, np.uint8)
    snap("start" if not seeds else f"seed fragments: {[(s[0], s[1], s[2].decode()) for s in seeds]}")

    if use_space:
        for p, (kb, _) in S.space_heuristic(arrs).items():
            if key[p] < 0:
                key[p] = kb
        snap("space heuristic")

    banned = set()
    for _ in range(max_iter):
        action, progressed = [], False
        done = 0
        for _, m, o, kb, w in _best_word_candidate(arrs, key, cribs, min_cover,
                                                   min_mean, ev_thr, banned):
            cur = key[o:o + len(kb)]
            if np.any((cur >= 0) & (cur != kb)) or not np.any(cur < 0):
                continue                # conflicts with what an earlier crib just fixed
            got = _commit_confident(arrs, key, o, kb, commit_margin)
            if got:
                action.append(f"crib {w.decode()!r} in {ids[m]} @ {o} ({got} bytes)")
                progressed = True
                done += 1
                if done >= max_per_round:
                    break
            else:
                banned.add((m, o, w))   # nothing confident: never retry this placement
        if extend:
            added = _extend_edges(arrs, key, min_cover, margin)
            if added:
                action.append(f"extended {added} positions")
                progressed = True
        if gap_fill:
            gf = _fill_gaps(arrs, key, min_cover, gap_margin)
            if gf:
                added2 = _extend_edges(arrs, key, min_cover, margin) if extend else 0
                action.append(f"gap search filled {gf} positions" + (f", extended {added2}" if added2 else ""))
                progressed = True
        if not progressed:
            break
        snap("; ".join(action))
    return res


# --------------------------------------------------------------------- CLI
def _show(ids, cts, key):
    for i in ids:
        print(f"{i}: {decrypt_partial(cts[i], key).decode('latin-1')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["rank", "recover"])
    ap.add_argument("--set", default="reuse", choices=["reuse", "control"])
    ap.add_argument("--path", help="override ciphertext file")
    ap.add_argument("--a", help="message that contains the crib (rank)")
    ap.add_argument("--b", help="use only this message for cross-checking (pair attack)")
    ap.add_argument("--crib", help="guessed plaintext fragment (rank)")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--seed", action="append", default=[], help='id:offset:text (recover)')
    args = ap.parse_args()

    path = args.path or config.PATHS[config.DATA_MODE][args.set]
    cts = load_set(path, args.set)
    ids = list(cts)
    print(f"[{config.DATA_MODE} data] {path} ({len(ids)} messages)")

    if args.cmd == "rank":
        arrs = [np.frombuffer(cts[i], np.uint8) for i in ids]
        a = ids.index(args.a)
        others = [ids.index(args.b)] if args.b else None
        crib = np.frombuffer(args.crib.encode(), np.uint8)
        score, valid = rank_crib(arrs, a, crib, others)
        for o in [o for o in np.argsort(-score) if valid[o]][:args.top]:
            print(f"offset {o:4d}  score {score[o]:6.2f}")
            for j in (others or [j for j in range(len(ids)) if j != a]):
                if len(arrs[j]) >= o + len(crib):
                    frag = bytes(arrs[j][o:o + len(crib)] ^ arrs[a][o:o + len(crib)] ^ crib)
                    print(f"     {ids[j]}: {frag.decode('latin-1')!r}")
    else:
        seeds = []
        for s in args.seed:
            mid, off, text = s.split(":", 2)
            seeds.append((mid, int(off), text.encode()))
        res = recover(cts, seeds=seeds)
        print(f"{len(res.history) - 1} iterations; known key bytes: "
              f"{int((res.key >= 0).sum())}/{len(res.key)}")
        _show(ids, cts, res.key)


if __name__ == "__main__":
    main()
