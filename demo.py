"""
Live demo for the CS 4379H Argon2 presentation.

    python demo.py                 # default password
    python demo.py "my password"   # hash your own password
    python demo.py --no-charts     # skip opening the result charts

What it shows, in order:
  1. Our pure-Python Argon2id hashes a password, and the tag is identical to
     the one from argon2-cffi (the reference C implementation).
  2. The same holds for Argon2d and Argon2i.
  3. Changing one character of the password changes the whole tag.
  4. Our implementation passes the official RFC 9106 test vectors.
  5. A real password-storage round trip with argon2-cffi's PasswordHasher
     (encoded "$argon2id$..." string, verify right and wrong passwords).
  6. Opens the experiment charts from results/figures/ (made by
     experiments.py).

Runs on Windows, macOS and Linux.
"""

import argparse
import os
import sys
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw

from argon2_impl import ARGON2D, ARGON2I, ARGON2ID, TYPE_NAMES, argon2_hash

HERE = os.path.dirname(os.path.abspath(__file__))
FIGURES = os.path.join(HERE, "results", "figures")

# Small parameters so the pure-Python version finishes in about a second.
SALT = b"cs4379h-demo-salt"        # fixed so the demo output is reproducible
T, M_KIB, P = 2, 256, 2
CFFI_TYPE = {ARGON2D: Type.D, ARGON2I: Type.I, ARGON2ID: Type.ID}


def heading(text):
    """Print a section heading."""
    print("\n" + text)
    print("-" * len(text))


def compare(password, type_):
    """Hash with our code and with argon2-cffi; print both tags and the timing."""
    t0 = time.perf_counter()
    ours = argon2_hash(password, SALT, time_cost=T, memory_kib=M_KIB,
                       parallelism=P, type_=type_)
    ours_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    ref = hash_secret_raw(password, SALT, T, M_KIB, P, 32, CFFI_TYPE[type_])
    ref_s = time.perf_counter() - t0

    name = TYPE_NAMES[type_]
    print(f"  {name:9} {'ours':11} {ours.hex()}   ({ours_s * 1000:7.1f} ms, Python)")
    print(f"  {name:9} {'argon2-cffi':11} {ref.hex()}   ({ref_s * 1000:7.1f} ms, C)")
    print(f"  {'':9} match: {'YES' if ours == ref else 'NO'}")
    return ours == ref


def bits_changed(a, b):
    """Number of differing bits between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def open_file(path):
    """Open a file with the operating system's default viewer."""
    if sys.platform == "win32":
        os.startfile(path)                                  # Windows
    elif sys.platform == "darwin":
        os.system(f'open "{path}"')                         # macOS
    else:
        os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')   # Linux


def main():
    """Run the demo steps described in the module docstring."""
    ap = argparse.ArgumentParser()
    ap.add_argument("password", nargs="?", default="correct horse battery staple")
    ap.add_argument("--no-charts", action="store_true", help="do not open the charts")
    args = ap.parse_args()
    pw = args.password.encode()

    print("Argon2 demo  (CS 4379H, Fall 2026)")
    print(f"password = {args.password!r}   salt = {SALT.decode()!r}")
    print(f"parameters: t = {T} passes, m = {M_KIB} KiB, p = {P} lanes, tag = 32 bytes")

    heading("1-2. Our implementation vs the reference C implementation")
    ok = all(compare(pw, y) for y in (ARGON2ID, ARGON2D, ARGON2I))

    heading("3. Avalanche: change one character of the password")
    other = pw[:-1] + bytes([pw[-1] ^ 1])
    a = argon2_hash(pw, SALT, time_cost=T, memory_kib=M_KIB, parallelism=P)
    b = argon2_hash(other, SALT, time_cost=T, memory_kib=M_KIB, parallelism=P)
    print(f"  {other.decode(errors='replace')!r}")
    print(f"  tag  {b.hex()}")
    print(f"  {bits_changed(a, b)} of 256 tag bits changed (about 128 expected)")

    heading("4. RFC 9106 test vectors (Section 5)")
    from test_argon2 import test_h0_matches_rfc, test_rfc_vectors
    test_rfc_vectors()
    test_h0_matches_rfc()
    print("  Argon2d, Argon2i, Argon2id tags and H0 match the RFC.")

    heading("5. Real password storage with argon2-cffi (OWASP-style settings)")
    ph = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)
    stored = ph.hash(args.password)
    print(f"  stored string: {stored}")
    print("  (salt, parameters and tag are all inside the string)")
    print(f"  verify(correct password): {ph.verify(stored, args.password)}")
    try:
        ph.verify(stored, args.password + "!")
        print("  verify(wrong password):   True   <-- should not happen")
    except VerifyMismatchError:
        print("  verify(wrong password):   rejected")

    heading("6. Experiment charts")
    charts = sorted(f for f in os.listdir(FIGURES) if f.endswith(".png")) \
        if os.path.isdir(FIGURES) else []
    if not charts:
        print("  No charts yet. Run:  python experiments.py")
    for f in charts:
        print(f"  {os.path.join('results', 'figures', f)}")
        if not args.no_charts:
            open_file(os.path.join(FIGURES, f))

    print("\nAll checks passed." if ok else "\nMISMATCH: see above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
