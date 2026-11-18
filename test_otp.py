"""Tests for otp_lib and for the data files.  Run with:  python -m unittest -v"""

import json
import random
import secrets
import unittest
from itertools import combinations

import run_all
from otp_lib import (KeyLengthError, KeyReuseError, OneTimePad, decrypt, encrypt,
                     generate_key, xor_bytes, xor_overlap)


class TestBasics(unittest.TestCase):

    def test_known_answer(self):
        # worked out by hand: 4F^1A=55, 54^2B=7F, 50^3C=6C
        key = bytes([0x1A, 0x2B, 0x3C])
        self.assertEqual(encrypt(b"OTP", key).hex(), "557f6c")
        self.assertEqual(decrypt(bytes.fromhex("557f6c"), key), b"OTP")

    def test_round_trip(self):
        for n in (1, 16, 200):
            message = secrets.token_bytes(n)
            key = generate_key(n)
            self.assertEqual(decrypt(encrypt(message, key), key), message)

    def test_ciphertext_same_length_as_message(self):
        self.assertEqual(len(encrypt(b"hello", generate_key(50))), 5)

    def test_key_too_short(self):
        with self.assertRaises(KeyLengthError):
            encrypt(b"hello world", generate_key(5))

    def test_generate_key(self):
        self.assertEqual(len(generate_key(32)), 32)
        self.assertNotEqual(generate_key(32), generate_key(32))
        with self.assertRaises(ValueError):
            generate_key(0)

    def test_seeded_key_is_reproducible(self):
        self.assertEqual(generate_key(20, random.Random(1)), generate_key(20, random.Random(1)))

    def test_text_must_be_encoded_first(self):
        with self.assertRaises(TypeError):
            encrypt("hello", generate_key(5))

    def test_xor_bytes_needs_same_length(self):
        with self.assertRaises(ValueError):
            xor_bytes(b"abc", b"ab")

    def test_xor_overlap(self):
        self.assertEqual(xor_overlap(b"abcdef", b"abc"), bytes(3))
        self.assertEqual(xor_overlap(b"abc", b"abcdef"), bytes(3))

    def test_space_flips_case(self):
        # this is why a space shows up as a letter in C1 xor C2
        self.assertEqual(xor_bytes(b"secret", b"      "), b"SECRET")


class TestHandExample(unittest.TestCase):
    """The hand-worked example from section 3.6 of the report."""

    P1 = b"attack at"
    P2 = b"hold fast"
    K = bytes.fromhex("3A91C75E0DB268F41B")
    C1 = bytes.fromhex("5BE5B33F6ED948956F")
    C2 = bytes.fromhex("52FEAB3A2DD409876F")
    D = bytes.fromhex("091B1805430D411200")

    def test_ciphertexts(self):
        self.assertEqual(encrypt(self.P1, self.K), self.C1)
        self.assertEqual(encrypt(self.P2, self.K), self.C2)

    def test_key_cancels(self):
        self.assertEqual(xor_bytes(self.C1, self.C2), self.D)
        self.assertEqual(xor_bytes(self.P1, self.P2), self.D)

    def test_crib(self):
        crib = b"attack"
        self.assertEqual(xor_bytes(crib, self.D[0:6]), b"hold f")
        # wrong offset gives garbage
        self.assertEqual(xor_bytes(crib, self.D[2:8]).hex(), "7971376c2279")

    def test_key_recovery(self):
        key_part = xor_bytes(self.C2[:6], b"hold f")
        self.assertEqual(key_part, self.K[:6])
        self.assertEqual(xor_bytes(self.C1[:6], key_part), b"attack")


class TestPad(unittest.TestCase):

    def test_sender_and_receiver(self):
        key = generate_key(30)
        sender, receiver = OneTimePad(key), OneTimePad(key)
        for message in (b"first message", b"second one", b"third"):
            self.assertEqual(receiver.decrypt(sender.encrypt(message)), message)
        self.assertEqual(sender.consumed, 28)

    def test_messages_use_different_key_bytes(self):
        key = bytes(range(1, 11))
        pad = OneTimePad(key)
        zeros = bytes(5)
        # encrypting zeros gives back the key bytes that were used
        self.assertEqual(pad.encrypt(zeros), key[:5])
        self.assertEqual(pad.encrypt(zeros), key[5:])

    def test_reuse_refused(self):
        pad = OneTimePad.generate(20)
        pad.encrypt(b"0123456789")
        with self.assertRaises(KeyReuseError):
            pad.encrypt(b"abc", offset=0)
        with self.assertRaises(KeyReuseError):
            pad.encrypt(b"abc", offset=8)  # bytes 8 and 9 are used, 10 is not
        self.assertEqual(pad.consumed, 10)

    def test_decrypt_also_uses_up_the_key(self):
        pad = OneTimePad.generate(10)
        pad.decrypt(b"12345")
        with self.assertRaises(KeyReuseError):
            pad.decrypt(b"12345", offset=0)

    def test_pad_runs_out(self):
        pad = OneTimePad.generate(10)
        pad.encrypt(b"1234567")
        with self.assertRaises(KeyLengthError):
            pad.encrypt(b"abcd")
        with self.assertRaises(KeyLengthError):
            OneTimePad(b"")

    def test_reuse_only_with_flag(self):
        pad = OneTimePad.generate(10, allow_reuse=True)
        c1 = pad.encrypt(b"attack", offset=0)
        c2 = pad.encrypt(b"defend", offset=0)
        self.assertEqual(xor_bytes(c1, c2), xor_bytes(b"attack", b"defend"))


class TestXorIdentity(unittest.TestCase):

    def setUp(self):
        self.messages = run_all.load_corpus()

    def test_holds_under_reuse_for_any_key(self):
        for _ in range(5):
            reuse, _ = run_all.make_sets(self.messages)
            for a, b in combinations(self.messages, 2):
                self.assertEqual(xor_overlap(reuse[a], reuse[b]),
                                 xor_overlap(self.messages[a], self.messages[b]))

    def test_fails_with_independent_keys(self):
        _, control = run_all.make_sets(self.messages)
        for a, b in combinations(self.messages, 2):
            self.assertNotEqual(xor_overlap(control[a], control[b]),
                                xor_overlap(self.messages[a], self.messages[b]))


class TestDataFiles(unittest.TestCase):

    def load(self, name):
        with open(run_all.DATA / name, encoding="utf-8") as f:
            return json.load(f)

    def test_files_follow_contract(self):
        for name, set_name in ((run_all.REUSE_FILE, "reuse"), (run_all.CONTROL_FILE, "control")):
            data = self.load(name)
            run_all.check_contract(data)
            self.assertEqual(data["set"], set_name)
            self.assertEqual(len(data["messages"]), 6)

    def test_contract_rejects_extra_fields(self):
        good = {"set": "reuse", "messages": [{"id": "m1", "ciphertext_hex": "00ff"}]}
        run_all.check_contract(good)
        bad = [
            {"set": "reuse", "messages": [{"id": "m1", "ciphertext_hex": "00ff", "plaintext": "x"}]},
            {"set": "reuse", "key": "00", "messages": good["messages"]},
            {"set": "other", "messages": good["messages"]},
            {"set": "reuse", "messages": [{"id": "m1", "ciphertext_hex": "xyz"}]},
            {"set": "reuse", "messages": []},
        ]
        for data in bad:
            with self.assertRaises(ValueError):
                run_all.check_contract(data)

    def test_ciphertext_lengths_match_corpus(self):
        messages = run_all.load_corpus()
        for name in (run_all.REUSE_FILE, run_all.CONTROL_FILE):
            cts = run_all.read_set(run_all.DATA / name)
            self.assertEqual({k: len(v) for k, v in cts.items()},
                             {k: len(v) for k, v in messages.items()})

    def test_files_match_the_seed(self):
        # the frozen files must be exactly what the fixed seed produces
        reuse, control = run_all.make_sets(run_all.load_corpus(), random.Random(run_all.SEED))
        self.assertEqual(self.load(run_all.REUSE_FILE), run_all.to_contract("reuse", reuse))
        self.assertEqual(self.load(run_all.CONTROL_FILE), run_all.to_contract("control", control))


if __name__ == "__main__":
    unittest.main()
