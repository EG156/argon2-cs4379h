"""
Verification suite for argon2_impl.py.

1. Official RFC 9106 test vectors (Section 5) for Argon2d, Argon2i, Argon2id.
2. Component tests: the pre-hashing digest H0 and intermediate memory blocks
   after each pass, as published in RFC 9106 Section 5.1. These localize a bug
   to H0, G, or indexing instead of only saying "the tag is wrong".
3. Randomized differential test against argon2-cffi (Python binding of the
   reference C implementation).

Run:  python -m pytest -q        (or)        python test_argon2.py
"""

import os
import random

from argon2.low_level import Type, hash_secret_raw

from argon2_impl import (ARGON2D, ARGON2I, ARGON2ID, argon2_hash, compute_h0)

# ---------------------------------------------------------------- RFC inputs
PW, SALT, SECRET, AD = b"\x01" * 32, b"\x02" * 16, b"\x03" * 8, b"\x04" * 12
RFC_PARAMS = dict(time_cost=3, memory_kib=32, parallelism=4, tag_len=32,
                  secret=SECRET, ad=AD)

RFC_TAGS = {
    ARGON2D:  "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
    ARGON2I:  "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
    ARGON2ID: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
}

RFC_ARGON2D_H0 = ("b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb8854917"
                  "17cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d17"
                  "9097a4af3109")

# (pass, block number, word index) -> expected 64-bit word, RFC 9106 Sec 5.1
RFC_ARGON2D_BLOCKS = {
    (0, 0, 0): 0xdb2fea6b2c6f5c8a, (0, 0, 1): 0x719413be00f82634,
    (0, 31, 127): 0x6a6c49d2cb75d5b6,
    (1, 0, 0): 0xd3801200410f8c0d, (1, 0, 1): 0x0bf9e8a6e442ba6d,
    (1, 31, 127): 0x2dbfff23f31b5883,
    (2, 0, 0): 0x5f047b575c5ff4d2, (2, 0, 1): 0xf06985dbf11c91a8,
    (2, 31, 127): 0xc341b3ca45c10da5,
}

CFFI_TYPE = {ARGON2D: Type.D, ARGON2I: Type.I, ARGON2ID: Type.ID}


# ---------------------------------------------------------------- tests
def test_rfc_vectors():
    for y, expected in RFC_TAGS.items():
        assert argon2_hash(PW, SALT, type_=y, **RFC_PARAMS).hex() == expected


def test_h0_matches_rfc():
    h0 = compute_h0(PW, SALT, SECRET, AD, p=4, tag_len=32, m=32, t=3, y=ARGON2D)
    assert h0.hex() == RFC_ARGON2D_H0


def test_intermediate_blocks_match_rfc():
    seen = {}

    def hook(pass_n, blocks):
        for (p_n, blk, word), _ in RFC_ARGON2D_BLOCKS.items():
            if p_n == pass_n:
                seen[(p_n, blk, word)] = blocks[blk][word]

    argon2_hash(PW, SALT, type_=ARGON2D, pass_hook=hook, **RFC_PARAMS)
    assert seen == RFC_ARGON2D_BLOCKS


def test_random_against_argon2_cffi(n_cases=60, seed=4379):
    rng = random.Random(seed)
    for _ in range(n_cases):
        y = rng.choice([ARGON2D, ARGON2I, ARGON2ID])
        p = rng.choice([1, 2, 3, 4])
        m = rng.randint(8 * p, 256)
        t = rng.randint(1, 4)
        tag_len = rng.choice([4, 16, 32, 64, 65, 100, 128])  # >64 exercises H'
        pw = os.urandom(rng.randint(0, 40))
        salt = os.urandom(rng.randint(8, 32))

        mine = argon2_hash(pw, salt, time_cost=t, memory_kib=m, parallelism=p,
                           tag_len=tag_len, type_=y)
        ref = hash_secret_raw(pw, salt, t, m, p, tag_len, CFFI_TYPE[y])
        assert mine == ref, f"mismatch: y={y} p={p} m={m} t={t} T={tag_len}"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS  {name}")
    print("All tests passed.")
