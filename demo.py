"""
Live demo for the CS 4379H Argon2 presentation (no slides: the terminal is
the presentation).

    python demo.py            # interactive menu
    python demo.py all        # run every section in order, pausing between them
    python demo.py 3          # run only section 3
    python demo.py all --no-pause --no-charts   # non-interactive check

Sections:
  1. Correctness   our pure-Python Argon2 vs the reference C code + RFC vectors
  2. Why slow      brute-force race: SHA-256 vs Argon2id on a 4-digit PIN
  3. Memory-hard   watch RAM jump as m goes 64 MiB -> 256 MiB -> 1 GiB
  4. Side channel  Argon2d memory reads depend on the password, Argon2i's don't
  5. Tradeoff      attacker keeps less memory -> recomputation cost explodes
  6. In practice   real password storage with the $argon2id$ string format
  7. Results       open the experiment charts from results/figures/

Runs on Windows, macOS and Linux.
"""

import argparse
import hashlib
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

# Set from the command line in main().
OPTIONS = {"pause": True, "charts": True, "password": "correct horse battery staple"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def heading(text):
    """Print a section heading."""
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def pause():
    """Wait for Enter so the presenter can talk before the next step."""
    if OPTIONS["pause"]:
        input("\n  [Enter to continue] ")


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


# ---------------------------------------------------------------------------
# 1. Correctness
# ---------------------------------------------------------------------------

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


def section_correctness():
    """Our implementation matches the reference C code and the RFC vectors."""
    heading("1. Correctness: our Argon2 vs the reference implementation")
    pw = OPTIONS["password"].encode()
    print(f"  password = {OPTIONS['password']!r}   salt = {SALT.decode()!r}")
    print(f"  t = {T} passes, m = {M_KIB} KiB, p = {P} lanes, 32-byte tag\n")
    ok = all(compare(pw, y) for y in (ARGON2ID, ARGON2D, ARGON2I))
    pause()

    print("\n  Avalanche: flip one bit of the last character")
    other = pw[:-1] + bytes([pw[-1] ^ 1])
    a = argon2_hash(pw, SALT, time_cost=T, memory_kib=M_KIB, parallelism=P)
    b = argon2_hash(other, SALT, time_cost=T, memory_kib=M_KIB, parallelism=P)
    print(f"  {other.decode(errors='replace')!r}")
    print(f"  tag  {b.hex()}")
    print(f"  {bits_changed(a, b)} of 256 tag bits changed (about 128 expected)")

    print("\n  RFC 9106 Section 5 test vectors")
    from test_argon2 import (test_h0_matches_rfc, test_intermediate_blocks_match_rfc,
                             test_rfc_vectors)
    test_rfc_vectors()
    test_h0_matches_rfc()
    test_intermediate_blocks_match_rfc()
    print("  Argon2d, Argon2i, Argon2id tags, H0, and memory after each pass: all match.")
    return ok


# ---------------------------------------------------------------------------
# 2. Brute-force race
# ---------------------------------------------------------------------------

def section_bruteforce(seconds=5.0):
    """Crack a 4-digit PIN stored with salted SHA-256 vs Argon2id."""
    heading("2. Why a slow hash: brute-forcing a 4-digit PIN")
    pin = b"7291"
    salt = b"0123456789abcdef"
    print("  A site stored the PIN 7291. The attacker stole the hash and the salt")
    print("  and tries 0000, 0001, ... until a hash matches.\n")

    # Fast hash: salted SHA-256.
    target = hashlib.sha256(salt + pin).digest()
    t0 = time.perf_counter()
    for n in range(10000):
        if hashlib.sha256(salt + f"{n:04d}".encode()).digest() == target:
            break
    sha_s = time.perf_counter() - t0
    sha_rate = (n + 1) / sha_s
    print(f"  SHA-256 : cracked {n:04d} after {n + 1:,} guesses in {sha_s * 1000:.1f} ms")
    pause()

    # Slow, memory-hard hash: Argon2id at the OWASP minimum (19 MiB, t=2, p=1).
    target = hash_secret_raw(pin, salt, 2, 19 * 1024, 1, 32, Type.ID)
    print(f"  Argon2id (19 MiB, t=2): guessing for {seconds:.0f} seconds...")
    t0 = time.perf_counter()
    tries, found = 0, False
    while time.perf_counter() - t0 < seconds and tries < 10000:
        guess = f"{tries:04d}".encode()
        tries += 1
        if hash_secret_raw(guess, salt, 2, 19 * 1024, 1, 32, Type.ID) == target:
            found = True
            break
    a_s = time.perf_counter() - t0
    rate = tries / a_s
    print(f"  Argon2id: {tries:,} guesses in {a_s:.1f} s ({rate:,.0f} per second),"
          f" {'found it' if found else 'not found yet'}")

    print(f"\n  Per guess, Argon2id is about {sha_rate / rate:,.0f}x slower here.")
    space = 26 ** 8
    print(f"  For an 8-letter lowercase password ({space:.1e} options), one CPU core:")
    print(f"    SHA-256  : {space / sha_rate / 3600:,.1f} hours")
    print(f"    Argon2id : {space / rate / 3600 / 24 / 365:,.0f} years")
    print("  GPUs speed up SHA-256 enormously; Argon2id's 19 MiB per guess limits")
    print("  how many guesses fit on a GPU at once (Experiment 2).")


# ---------------------------------------------------------------------------
# 3. Memory-hardness, live
# ---------------------------------------------------------------------------

def section_memory():
    """Show peak RAM of one Argon2id hash for growing m."""
    heading("3. Memory-hard: the RAM cost is real")
    print("  Open Task Manager (Windows) or Activity Monitor (Mac) to watch.\n")
    from experiments import peak_rss_kib
    for mib in (64, 256, 1024):
        t0 = time.perf_counter()
        peak = peak_rss_kib(mib * 1024, 3, 4)     # fresh process, t=3, p=4
        sec = time.perf_counter() - t0
        print(f"  m = {mib:5} MiB  ->  peak extra RAM {peak / 1024:7.0f} MiB"
              f"   ({sec:.1f} s incl. process start)")
    print("\n  Peak memory tracks m. An attacker cannot skip storing it without")
    print("  paying in recomputation (section 5).")


# ---------------------------------------------------------------------------
# 4. Side channel: data-dependent vs data-independent addressing
# ---------------------------------------------------------------------------

def reference_columns(password, type_, n_blocks=32, show=14):
    """Columns read (reference blocks) for the first blocks of a tiny hash."""
    trace = {}
    argon2_hash(password, SALT, time_cost=1, memory_kib=n_blocks, parallelism=1,
                type_=type_, trace=trace)
    return [dep[5] for dep in trace["deps"]][:show]


def section_side_channel():
    """Argon2d's memory reads depend on the password; Argon2i's do not."""
    heading("4. Side channel: which memory blocks get read?")
    print("  Each new block mixes in one earlier 'reference' block. These are the")
    print("  reference block numbers for blocks 2..15 of a tiny 32-block hash.\n")
    for y in (ARGON2D, ARGON2I):
        r1 = reference_columns(b"hunter2", y)
        r2 = reference_columns(b"letmein", y)
        print(f"  {TYPE_NAMES[y]}")
        print(f"    password 'hunter2': {r1}")
        print(f"    password 'letmein': {r2}")
        print(f"    same pattern? {'YES' if r1 == r2 else 'NO'}\n")
    print("  Argon2d: the access pattern leaks information about the password to")
    print("  anyone who can watch cache timing. Argon2i: the pattern depends only")
    print("  on public values, so there is nothing to leak. Argon2id does the")
    print("  Argon2i rule first, then switches to Argon2d (the RFC's recommendation).")


# ---------------------------------------------------------------------------
# 5. Tradeoff attack
# ---------------------------------------------------------------------------

def section_tradeoff():
    """Attacker stores 1/k of memory; show the recomputation penalty."""
    heading("5. Tradeoff attack: what if the attacker saves memory?")
    from experiments import PAPER_TABLE_I, attack_cost, dependency_graph, store_hybrid
    n = 4096
    print(f"  1-pass Argon2d, {n} blocks. The attacker keeps only 1/k of the blocks")
    print("  and recomputes the missing ones when they are needed.\n")
    ref = dependency_graph(n, ARGON2D)
    print(f"  {'memory kept':>12} {'our extra work C':>18} {'paper Table I C':>17}")
    for k in range(2, 8):
        c, _ = attack_cost(ref, store_hybrid(ref, n // k, 0.8))
        paper = PAPER_TABLE_I[f"1/{k}"][0]
        print(f"  {'1/' + str(k):>12} {c:>17,.1f}x {paper:>16,.1f}x")
        time.sleep(0.4)       # let the numbers land one at a time
    print("\n  Halving memory costs ~1.5x work; keeping 1/7 costs millions of")
    print("  times more. There is no cheap way to save memory.")
    print("  (The paper's smarter ranking attack does better than ours below 1/3.)")


# ---------------------------------------------------------------------------
# 6. Real password storage
# ---------------------------------------------------------------------------

def section_storage():
    """Store and verify a password the way a real web app would."""
    heading("6. In practice: storing a password")
    pw = OPTIONS["password"]
    ph = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)
    stored = ph.hash(pw)
    print(f"  stored string:\n    {stored}\n")
    print("  $argon2id = variant, v=19 = version 1.3, m/t/p = cost parameters,")
    print("  then the random salt and the tag (base64). One string is all a")
    print("  database needs.\n")
    print(f"  verify({pw!r}): {ph.verify(stored, pw)}")
    try:
        ph.verify(stored, pw + "!")
        print("  verify(wrong password): True   <-- should not happen")
    except VerifyMismatchError:
        print(f"  verify({pw + '!'!r}): rejected")
    print("\n  Hash the same password again -> different string (new salt):")
    print(f"    {ph.hash(pw)}")


# ---------------------------------------------------------------------------
# 7. Charts
# ---------------------------------------------------------------------------

def section_charts():
    """Open the experiment charts made by experiments.py."""
    heading("7. Experiment results")
    charts = sorted(f for f in os.listdir(FIGURES) if f.endswith(".png")) \
        if os.path.isdir(FIGURES) else []
    if not charts:
        print("  No charts yet. Run:  python experiments.py")
    for f in charts:
        print(f"  {os.path.join('results', 'figures', f)}")
        if OPTIONS["charts"]:
            open_file(os.path.join(FIGURES, f))


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

SECTIONS = [
    ("Correctness: our code vs reference C + RFC vectors", section_correctness),
    ("Why slow: brute-force race, SHA-256 vs Argon2id", section_bruteforce),
    ("Memory-hard: RAM use at 64 MiB / 256 MiB / 1 GiB", section_memory),
    ("Side channel: Argon2d vs Argon2i memory reads", section_side_channel),
    ("Tradeoff attack: less memory -> much more work", section_tradeoff),
    ("In practice: storing and verifying a password", section_storage),
    ("Results: open the experiment charts", section_charts),
]


def run(i):
    """Run section i (1-based)."""
    SECTIONS[i - 1][1]()


def run_all():
    """Run every section in order, pausing between them."""
    for i in range(1, len(SECTIONS) + 1):
        run(i)
        pause()


def menu():
    """Interactive menu loop."""
    while True:
        print("\nArgon2 demo  (CS 4379H, Fall 2026)")
        for i, (name, _) in enumerate(SECTIONS, 1):
            print(f"  {i}. {name}")
        print("  a. run all      q. quit")
        choice = input("> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return
        if choice in ("a", "all"):
            run_all()
        elif choice.isdigit() and 1 <= int(choice) <= len(SECTIONS):
            run(int(choice))
            pause()


def main():
    """Parse arguments, then run the menu, one section, or all sections."""
    ap = argparse.ArgumentParser(description="Argon2 live demo")
    ap.add_argument("section", nargs="?", default=None,
                    help="section number 1-7, or 'all'; omit for the menu")
    ap.add_argument("--password", default=OPTIONS["password"])
    ap.add_argument("--no-pause", action="store_true", help="do not wait for Enter")
    ap.add_argument("--no-charts", action="store_true", help="do not open chart windows")
    args = ap.parse_args()
    OPTIONS.update(password=args.password, pause=not args.no_pause,
                   charts=not args.no_charts)

    if args.section is None:
        menu()
    elif args.section == "all":
        run_all()
    else:
        run(int(args.section))
    return 0


if __name__ == "__main__":
    sys.exit(main())
