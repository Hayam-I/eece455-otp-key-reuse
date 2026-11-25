"""Tests for code.  Run:  python -m pytest -q test_crib_drag.py

Known-answer test: uses data/hand_example.json (B's hand example) if present,
otherwise the placeholder written by make_dummy.py.  Same fields either way.
"""
import json
import random
from pathlib import Path

import numpy as np
import pytest

import config
import crib_drag as cd
import scoring as S

DATA = Path(__file__).resolve().parent / "data"


def _hand():
    p = DATA / "hand_example.json"
    if not p.exists():
        p = DATA / "dummy" / "hand_example_placeholder.json"
    return json.loads(p.read_text())


def test_xor_identity_on_hand_example():
    h = _hand()
    c1, c2 = bytes.fromhex(h["c1_hex"]), bytes.fromhex(h["c2_hex"])
    assert cd.xor_bytes(c1, c2) == cd.xor_bytes(h["p1"].encode(), h["p2"].encode())
    assert cd.xor_bytes(c1, c2).hex() == h["d_hex"]


def test_known_answer_crib_at_correct_and_wrong_offset():
    h = _hand()
    c1, c2 = bytes.fromhex(h["c1_hex"]), bytes.fromhex(h["c2_hex"])
    crib, o, w = h["crib"].encode(), h["crib_offset"], h["wrong_offset"]
    good = cd.fragment_at(c1, c2, crib, o)
    assert good == h["p2"].encode()[o:o + len(crib)]            # reveals the other message
    assert cd.fragment_at(c1, c2, crib, w) != h["p2"].encode()[w:w + len(crib)]


def test_attack_is_independent_of_key_value():
    """Same plaintexts under two different keys: identical C1^C2, identical ranking."""
    plain = [m["plaintext"].encode() for m in json.loads(
        (DATA / "dummy" / "corpus_dummy.json").read_text())["messages"][:2]]
    n = min(map(len, plain))
    results = []
    for seed in (1, 2):
        key = random.Random(seed).randbytes(n)
        cts = [cd.xor_bytes(p[:n], key) for p in plain]
        arrs = [np.frombuffer(c, np.uint8) for c in cts]
        crib = plain[0][10:18]
        score, valid = cd.rank_crib(arrs, 0, np.frombuffer(crib, np.uint8), [1])
        results.append((cd.xor_bytes(*cts), score))
    assert results[0][0] == results[1][0]
    assert np.allclose(results[0][1], results[1][1])


def test_load_set_enforces_data_contract(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"set": "reuse", "messages": [
        {"id": "m1", "ciphertext_hex": "00ff", "plaintext": "no"},
        {"id": "m2", "ciphertext_hex": "0a0b"}]}))
    with pytest.raises(ValueError):
        cd.load_set(bad, "reuse")
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"set": "control", "messages": [
        {"id": "m1", "ciphertext_hex": "00ff"}, {"id": "m2", "ciphertext_hex": "0a0b"}]}))
    with pytest.raises(ValueError):                              # wrong set label
        cd.load_set(ok, "reuse")
    assert cd.load_set(ok, "control")["m1"] == b"\x00\xff"


def test_scoring_prefers_english_over_noise():
    english = np.frombuffer(b"the committee has reviewed", np.uint8)[None, :]
    noise = np.frombuffer(bytes(random.Random(0).randbytes(26)), np.uint8)[None, :]
    assert S.combined_score(english)[0] > S.combined_score(noise)[0] + 2


def _dummy(set_name):
    P = config.PATHS["dummy"]
    return cd.load_set(P[set_name], set_name), cd.load_corpus(P["corpus"])


def test_crib_ranking_reuse_beats_control():
    def top3(set_name, L=8):
        cts, plains = _dummy(set_name)
        ids = list(cts)
        arrs = [np.frombuffer(cts[i], np.uint8) for i in ids]
        hits = tot = 0
        for ia in range(len(ids)):
            for ib in range(len(ids)):
                if ia == ib:
                    continue
                ov = min(len(plains[ids[ia]]), len(plains[ids[ib]]))
                for o in range(0, ov - L + 1, 7):
                    crib = plains[ids[ia]][o:o + L]
                    sc, va = cd.rank_crib(arrs, ia, np.frombuffer(crib, np.uint8), [ib])
                    hits += cd.rank_stats(sc, va, o)[0][3]
                    tot += 1
        return hits / tot
    assert top3("reuse") > 0.9
    assert top3("control") < 0.15


def test_recovery_on_reuse_and_nothing_on_control():
    cts, plains = _dummy("reuse")
    res = cd.recover(cts)
    k = res.key
    known = int((k >= 0).sum())
    right = sum(1 for p in range(len(k)) if k[p] >= 0 and
                all((cts[i][p] ^ int(k[p])) == plains[i][p] for i in cts if len(cts[i]) > p))
    assert known > 150 and right / known > 0.9
    ctl, _ = _dummy("control")
    assert int((cd.recover(ctl).key >= 0).sum()) == 0


def test_real_data_reuse_recovers_and_control_does_not():
    P = config.PATHS["real"]
    if not all(Path(p).exists() for p in P.values()):
        pytest.skip("real data files not present")
    reuse, ctl = cd.load_set(P["reuse"], "reuse"), cd.load_set(P["control"], "control")
    plains = cd.load_corpus(P["corpus"])
    longest = max(plains, key=lambda i: len(plains[i]))
    true_key = [reuse[longest][p] ^ plains[longest][p] for p in range(len(plains[longest]))]
    k = cd.recover(reuse).key
    known = [p for p in range(len(k)) if k[p] >= 0]
    right = sum(1 for p in known if k[p] == true_key[p])
    assert len(known) > 200 and right / len(known) > 0.95
    assert int((cd.recover(ctl).key >= 0).sum()) == 0
