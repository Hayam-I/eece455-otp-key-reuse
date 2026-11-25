"""make_dummy.py - temporary data in the agreed data contract.

Generates, from PLACEHOLDER plaintexts under ONE reused key:
  data/dummy/ciphertexts_reuse.json     {"set": "reuse",   "messages": [{"id","ciphertext_hex"}, ...]}
  data/dummy/ciphertexts_control.json   {"set": "control", ...}  (independent key per message)
  data/dummy/corpus_dummy.json          ground truth, used ONLY by evaluate.py for scoring
  data/dummy/hand_example_placeholder.json   stand-in for B's hand example (same fields)

Dummy data must never appear in final results: evaluate.py writes dummy runs
to results/dummy/ and stamps every figure "DUMMY DATA".
Fixed seed, so the files are reproducible.  Keys here are NOT secure
otp_lib.py uses os.urandom/secrets for the real data.
"""
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent / "data" / "dummy"
SEED = 1234

# Six invented placeholder messages, ASCII, 80-400 characters, varied length.
PLACEHOLDERS = [
    "Shipment of grain will leave the northern depot on Tuesday. "
    "Confirm receipt at the usual place.",
    "The committee has reviewed the proposal and finds the cost too high for "
    "this season. We ask that the supplier reduce the price by one fifth "
    "before the contract is signed on Friday.",
    "Our representative arrived in the city on the ninth and met the two "
    "gentlemen as arranged. They have agreed to provide the maps, but they "
    "want payment in advance and a guarantee that their names will not be "
    "mentioned in any report. Please advise how much we may offer.",
    "Regarding your question about the machines: the first group was tested "
    "last week and worked well, although the engineers say that the cooling "
    "system must be changed before the second group can be put into use. "
    "The delay should not be longer than three weeks.",
    "Please send the figures for the month of March together with the list "
    "of all goods that are still waiting at the harbour.",
    "In reply to your letter of the fourth, we regret that the meeting cannot "
    "take place at the time proposed, since the main speaker is unwell and "
    "the hall has been promised to another group for the whole afternoon. "
    "We suggest the following Wednesday, in the morning, and we will inform "
    "all members by telephone once you have confirmed. The agenda remains "
    "unchanged.",
]

# Placeholder for B's hand example (replace with B's real values; same fields).
HAND_P1 = "ATTACK AT"
HAND_P2 = "MEET NEAR"
HAND_KEY = bytes.fromhex("a35f1c88e207d46b39")
HAND_CRIB = "ATTACK"        # crib in P1 at the correct offset 0 -> reveals P2[0:6]
HAND_CRIB_OFFSET = 0
HAND_WRONG_OFFSET = 2


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    plains = [p.encode("ascii") for p in PLACEHOLDERS]
    assert all(80 <= len(p) <= 400 for p in plains), [len(p) for p in plains]
    ids = [f"m{i + 1}" for i in range(len(plains))]
    longest = max(len(p) for p in plains)

    key = rng.randbytes(longest)                       # ONE key, reused
    reuse = [{"id": i, "ciphertext_hex": xor(p, key).hex()}
             for i, p in zip(ids, plains)]
    control = [{"id": i, "ciphertext_hex": xor(p, rng.randbytes(longest)).hex()}
               for i, p in zip(ids, plains)]            # fresh key per message

    write_json(OUT / "ciphertexts_reuse.json", {"set": "reuse", "messages": reuse})
    write_json(OUT / "ciphertexts_control.json", {"set": "control", "messages": control})
    write_json(OUT / "corpus_dummy.json", {"messages": [
        {"id": i, "plaintext": p.decode()} for i, p in zip(ids, plains)]})

    p1, p2 = HAND_P1.encode(), HAND_P2.encode()
    c1, c2 = xor(p1, HAND_KEY), xor(p2, HAND_KEY)
    write_json(OUT / "hand_example_placeholder.json", {
        "NOTE": "PLACEHOLDER - replace with B's hand example (same fields).",
        "p1": HAND_P1, "p2": HAND_P2, "k_hex": HAND_KEY.hex(),
        "c1_hex": c1.hex(), "c2_hex": c2.hex(), "d_hex": xor(c1, c2).hex(),
        "crib": HAND_CRIB, "crib_offset": HAND_CRIB_OFFSET,
        "wrong_offset": HAND_WRONG_OFFSET,
    })
    print(f"wrote dummy files to {OUT}")
    print("message lengths:", [len(p) for p in plains])


if __name__ == "__main__":
    main()
