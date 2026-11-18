"""
One-time pad library for the EECE 455 project (VENONA and OTP key reuse).

    C = P xor K
    P = C xor K

generate_key / encrypt / decrypt are the basic functions.
OneTimePad is the pad manager: it remembers which key bytes were already
used and refuses to use them a second time.
"""

import secrets


class KeyLengthError(ValueError):
    """Not enough key bytes for the message."""


class KeyReuseError(Exception):
    """Tried to use key bytes that were already used."""


def xor_bytes(a, b):
    """XOR two byte strings of the same length."""
    if len(a) != len(b):
        raise ValueError(f"lengths differ ({len(a)} and {len(b)})")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_overlap(a, b):
    """XOR two byte strings aligned at byte 0, keeping only the overlapping part.

    Used for messages of different lengths: the extra tail of the longer
    message has nothing to be XORed with, so it is dropped.
    """
    n = min(len(a), len(b))
    return xor_bytes(a[:n], b[:n])


def generate_key(n, rng=None):
    """Return n random key bytes.

    The default source is secrets.token_bytes (secure random from the OS).
    Passing a seeded random.Random as rng is only for the demo files, so that
    everyone gets the same ciphertexts. A seeded generator is predictable, so
    it is not a proper OTP key source.
    """
    if n < 1:
        raise ValueError("key length must be at least 1")
    if rng is None:
        return secrets.token_bytes(n)
    return rng.randbytes(n)


def encrypt(plaintext, key):
    """C = P xor K. The key has to be at least as long as the message."""
    if len(key) < len(plaintext):
        raise KeyLengthError(
            f"key is {len(key)} bytes but the message is {len(plaintext)} bytes"
        )
    return xor_bytes(plaintext, key[:len(plaintext)])


def decrypt(ciphertext, key):
    """P = C xor K, which is the same operation as encrypt."""
    return encrypt(ciphertext, key)


class OneTimePad:
    """A pad of key bytes that keeps track of what has been used.

    encrypt() and decrypt() take the next unused bytes, or the bytes starting
    at `offset` if one is given. Using a byte twice raises KeyReuseError and
    running out of bytes raises KeyLengthError.

    allow_reuse=True turns the reuse check off. That is only for the key
    reuse experiment, never for normal use.

    Sender and receiver each have their own OneTimePad made from the same key
    and go through it in the same order.
    """

    def __init__(self, key, allow_reuse=False):
        if len(key) == 0:
            raise KeyLengthError("the pad is empty")
        self._key = bytes(key)
        self._used = [False] * len(key)
        self._next = 0  # where the next message starts if no offset is given
        self.allow_reuse = allow_reuse

    @classmethod
    def generate(cls, n, allow_reuse=False, rng=None):
        """Make a pad with n new key bytes."""
        return cls(generate_key(n, rng), allow_reuse)

    def __len__(self):
        return len(self._key)

    @property
    def consumed(self):
        """How many key bytes have been used so far."""
        return sum(self._used)

    def _take(self, n, offset):
        start = self._next if offset is None else offset
        end = start + n
        if start < 0:
            raise ValueError("offset cannot be negative")
        if end > len(self._key):
            raise KeyLengthError(
                f"pad has {len(self._key)} bytes, cannot use bytes {start} to {end - 1}"
            )
        if any(self._used[start:end]) and not self.allow_reuse:
            raise KeyReuseError(
                f"key bytes between {start} and {end - 1} were already used"
            )
        for i in range(start, end):
            self._used[i] = True
        self._next = max(self._next, end)
        return self._key[start:end]

    def encrypt(self, plaintext, offset=None):
        return xor_bytes(plaintext, self._take(len(plaintext), offset))

    def decrypt(self, ciphertext, offset=None):
        return xor_bytes(ciphertext, self._take(len(ciphertext), offset))
