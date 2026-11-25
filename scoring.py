"""scoring.py - rank candidate plaintext fragments.

Three ingredients, all computed from ciphertext-derived candidates only:
  1. printable-character ratio
  2. English letter + bigram log-likelihood (class-level model, see below)
  3. the "space heuristic" from B's analytic prediction:
       space XOR letter  ->  a letter-range byte (0x41-0x5A / 0x61-0x7A)

The attack never sees plaintext. Ground truth is used only in evaluate.py.

Language model
--------------
Characters are folded into 30 classes: 26 letters (case folded), space, digit,
'.' or ',', other printable.  Non-printable bytes get a fixed large penalty.
Unigram probabilities come from published English letter frequencies
(Lewand) scaled by typical letter/space shares.  Bigram probabilities are
estimated from a small built-in training text and smoothed toward the unigram
model, so a small training text still gives a usable model.  A larger text
can be supplied with set_training_text().  IMPORTANT: never train on
corpus.json - that would leak the answer into the scorer.
"""
import math
import numpy as np

# ---------------------------------------------------------------- constants
# Published English letter frequencies, percent (Lewand).
LETTER_FREQ = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75,
    "s": 6.33, "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78,
    "u": 2.76, "m": 2.41, "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97,
    "p": 1.93, "b": 1.49, "v": 0.98, "k": 0.77, "j": 0.15, "x": 0.15,
    "q": 0.10, "z": 0.07,
}
# Shares of running text (letters, space, digits, ". ,", other printable).
SHARE_LETTERS, SHARE_SPACE, SHARE_DIGIT, SHARE_STOP, SHARE_OTHER = (
    0.76, 0.18, 0.01, 0.03, 0.02)

N_CLASSES = 30          # 0-25 letters, 26 space, 27 digit, 28 '.' ','  29 other
C_SPACE, C_DIGIT, C_STOP, C_OTHER = 26, 27, 28, 29
NONPRINT_LOGP = -12.0   # log-prob charged to a non-printable byte
UPPER_PENALTY = -0.7    # mild penalty for upper case (text is mostly lower)
PR_WEIGHT = 5.0         # weight of the printable ratio in the combined score
BIGRAM_PRIOR = 20.0     # pseudo-count pulling bigrams toward the unigram model

# Small generic English text for the bigram model (not from the project corpus).
DEFAULT_TRAIN_TEXT = """
The weather was cold and the road to the village was long. Nobody expected the
train to arrive before noon, so the travellers sat together in the station and
talked about the news from the capital. One of them had a letter that he
wished to send, but the office was closed until the next morning. They agreed
that it would be wise to wait, and that the matter could be settled in the
afternoon. In the meantime the shopkeeper brought bread, cheese and hot tea,
and everyone thanked him for his kindness. When the evening came the wind grew
stronger, and the old clock above the door struck seven. The manager of the
railway said that the line would be open again by the end of the week, though
he could not promise anything. Several people had already decided to walk
home across the fields, because they had work to finish and families who were
waiting for them. There were two hundred and fifty men at the factory, and
most of them lived within five miles of the town. The committee will meet on
Thursday to discuss the plan for the new bridge, which should be built before
the winter. We have received your message and we will send an answer as soon
as the report is ready. Please confirm that the goods have been delivered to
the warehouse, and tell us when the payment will arrive. The government has
announced that the borders will remain closed, and that further information
will be given to the public in due course. It is important that every member
of the group understands what is required, and that nothing is said about the
arrangements to anyone outside the office. This is the last time that we shall
write on this subject, and we hope that you will find the terms acceptable.
"""

# ------------------------------------------------------------ class mapping
def _byte_class(b: int) -> int:
    if 97 <= b <= 122:
        return b - 97
    if 65 <= b <= 90:
        return b - 65
    if b == 32:
        return C_SPACE
    if 48 <= b <= 57:
        return C_DIGIT
    if b in (44, 46):
        return C_STOP
    if 33 <= b <= 126 or b == 10:
        return C_OTHER
    return N_CLASSES  # non-printable


CLS = np.array([_byte_class(b) for b in range(256)], dtype=np.intp)
PRINTABLE = CLS < N_CLASSES
IS_UPPER = np.array([65 <= b <= 90 for b in range(256)])

UNI = BI = None  # filled by set_training_text()


def _unigram_probs() -> np.ndarray:
    total = sum(LETTER_FREQ.values())
    p = np.zeros(N_CLASSES)
    for ch, f in LETTER_FREQ.items():
        p[ord(ch) - 97] = SHARE_LETTERS * f / total
    p[C_SPACE], p[C_DIGIT] = SHARE_SPACE, SHARE_DIGIT
    p[C_STOP], p[C_OTHER] = SHARE_STOP, SHARE_OTHER
    return p / p.sum()


def set_training_text(text: str) -> None:
    """(Re)build the byte-level unigram/bigram log-probability tables."""
    global UNI, BI
    pu = _unigram_probs()
    counts = np.zeros((N_CLASSES, N_CLASSES))
    prev = None
    for ch in text:
        b = ord(ch) if ord(ch) < 256 else 63
        c = _byte_class(b)
        if c >= N_CLASSES:          # newline etc. handled as 'other'
            c = C_OTHER if b in (9, 10, 13) else None
        if prev is not None and c is not None:
            counts[prev, c] += 1
        prev = c
    row = counts.sum(axis=1, keepdims=True)
    pb = (counts + BIGRAM_PRIOR * pu[None, :]) / (row + BIGRAM_PRIOR)
    logp = np.zeros((N_CLASSES + 1, N_CLASSES + 1))
    logp[:N_CLASSES, :N_CLASSES] = np.log(pb)
    logp[:N_CLASSES, N_CLASSES] = NONPRINT_LOGP     # next byte non-printable
    logp[N_CLASSES, :N_CLASSES] = np.log(pu)        # context lost: unigram
    logp[N_CLASSES, N_CLASSES] = NONPRINT_LOGP
    BI = logp[CLS[:, None], CLS[None, :]].copy()
    BI += np.where(IS_UPPER, UPPER_PENALTY, 0.0)[None, :]
    UNI = logp[N_CLASSES, CLS].copy()
    UNI += np.where(IS_UPPER, UPPER_PENALTY, 0.0)


set_training_text(DEFAULT_TRAIN_TEXT)


# ----------------------------------------------------------------- scoring
def printable_ratio(frags: np.ndarray) -> np.ndarray:
    """Fraction of printable bytes per fragment. frags: (n, L) uint8."""
    return PRINTABLE[frags].mean(axis=1)


def loglik_per_char(frags: np.ndarray) -> np.ndarray:
    """Mean unigram+bigram log-likelihood per character, per fragment."""
    f = frags.astype(np.intp)
    L = f.shape[1]
    ll = UNI[f[:, 0]].copy()
    if L > 1:
        ll += BI[f[:, :-1], f[:, 1:]].sum(axis=1)
    return ll / L


def combined_score(frags: np.ndarray) -> np.ndarray:
    """Ranking score: log-likelihood per char plus a printable-ratio term."""
    frags = np.atleast_2d(frags)
    return loglik_per_char(frags) + PR_WEIGHT * (printable_ratio(frags) - 1.0)


def score_bytes(data: bytes) -> float:
    return float(combined_score(np.frombuffer(data, np.uint8)[None, :])[0])


# --------------------------------------------------------- space heuristic
# B's prediction: a space XOR a letter lands in 0x41-0x5A (letter was lower
# case) or 0x61-0x7A (letter was upper case); two letters XOR into 0x00-0x3F.
SPACE_PARAMS = {"vote_threshold": 0.8, "min_others": 2}


def _is_letter_byte(d: np.ndarray) -> np.ndarray:
    return ((d >= 0x41) & (d <= 0x5A)) | ((d >= 0x61) & (d <= 0x7A))


def space_heuristic(arrs, vote_threshold=None, min_others=None):
    """Guess key bytes at positions where one ciphertext probably holds a space.

    arrs: list of uint8 arrays (ciphertexts, aligned at byte 0).
    At position p, message m is a 'space candidate' if, for at least
    `vote_threshold` of the other messages n covering p, C_m[p]^C_n[p] is a
    letter-range byte.  Then K[p] = C_m[p] ^ 0x20.  Among candidates the one
    whose implied column looks most like English wins; the whole column must
    decrypt to printable bytes.
    Returns {position: (key_byte, vote_fraction)}.
    """
    thr = SPACE_PARAMS["vote_threshold"] if vote_threshold is None else vote_threshold
    min_o = SPACE_PARAMS["min_others"] if min_others is None else min_others
    L = max(len(a) for a in arrs)
    out = {}
    for p in range(L):
        cov = [j for j, a in enumerate(arrs) if len(a) > p]
        if len(cov) < min_o + 1:
            continue
        col = np.array([arrs[j][p] for j in cov], dtype=np.uint8)
        best = None
        for idx in range(len(cov)):
            others = np.delete(col, idx)
            frac = _is_letter_byte(col[idx] ^ others).mean()
            if frac < thr:
                continue
            k = int(col[idx] ^ 0x20)
            plain = col ^ np.uint8(k)
            if not PRINTABLE[plain].all():
                continue
            s = float(UNI[plain].sum())
            if best is None or s > best[0]:
                best = (s, k, frac)
        if best is not None:
            out[p] = (best[1], best[2])
    return out
