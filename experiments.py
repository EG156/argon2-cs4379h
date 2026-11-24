"""
Experiments for the Argon2 project. Each experiment writes a CSV into results/
and a chart into results/figures/, so every number in the slides can be
reproduced with one command:

    python experiments.py            # all experiments (about 2 to 4 minutes)
    python experiments.py --quick    # smaller sizes, for a fast check

Experiment 1  Cost scaling: time and peak memory vs m, t, p (argon2-cffi, C code)
Experiment 2  Per-guess cost of Argon2id vs PBKDF2 and bcrypt
Experiment 3  G-call counts of our own implementation (exact work vs t*m)
Experiment 4  Time-memory tradeoff attack on 1-pass Argon2d, compared to the
              paper's Table I
"""

import argparse
import csv
import hashlib
import os
import statistics
import subprocess
import sys
import time

import bcrypt
from argon2.low_level import Type, hash_secret_raw

import argon2_impl
from argon2_impl import ARGON2D, ARGON2I, ARGON2ID, argon2_hash

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
FIGURES = os.path.join(RESULTS, "figures")

# Chart styling: fixed categorical order, thin lines, recessive grid.
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK, INK2, SURFACE = "#0b0b0b", "#52514e", "#fcfcfb"


def write_csv(name, header, rows):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  wrote {os.path.relpath(path, HERE)}")


def timed(fn, repeats):
    """Median wall-clock time of fn() over `repeats` runs, in seconds."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


# Runs in a fresh child process so earlier experiments don't inflate the peak.
# Works on Windows, macOS and Linux:
#   Windows       -> psutil's peak working set (bytes)
#   macOS         -> resource.ru_maxrss is reported in BYTES
#   Linux         -> VmHWM from /proc/self/status (KiB). ru_maxrss is NOT used
#                    on Linux because a child inherits its parent's peak value.
_PEAK_RSS_CHILD = r"""
import sys
from argon2.low_level import hash_secret_raw, Type

def peak_kib():
    if sys.platform == "win32":
        import psutil
        return psutil.Process().memory_info().peak_wset / 1024
    if sys.platform.startswith("linux"):
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024   # macOS

m, t, p = (int(x) for x in sys.argv[1:4])
base = peak_kib()
hash_secret_raw(b"pw", b"somesalt", t, m, p, 32, Type.ID)
print(int(peak_kib() - base))
"""


def peak_rss_kib(m, t, p):
    """Peak extra memory (KiB) used by one Argon2id hash with these parameters."""
    out = subprocess.run([sys.executable, "-c", _PEAK_RSS_CHILD, str(m), str(t), str(p)],
                         capture_output=True, text=True, check=True)
    return int(out.stdout.strip())


# ---------------------------------------------------------------------------
# Experiment 1: cost scaling
# ---------------------------------------------------------------------------

def exp1_scaling(quick):
    print("Experiment 1: cost scaling with m, t, p (argon2-cffi)")
    mems = [1024, 4096, 16384, 65536] if quick else [1024, 4096, 16384, 65536, 262144]
    # Memory is measured first, before this process hashes anything large.
    peaks = {m: peak_rss_kib(m, 3, 1) for m in mems}
    rows_m = []
    for m in mems:
        sec = timed(lambda: hash_secret_raw(b"pw", b"somesalt", 3, m, 1, 32, Type.ID), 5)
        rows_m.append((m, 3, 1, round(sec * 1000, 2), peaks[m]))
    write_csv("exp1_memory.csv", ["m_kib", "t", "p", "time_ms", "peak_rss_kib"], rows_m)

    rows_t = []
    for t in [1, 2, 3, 4, 6, 8]:
        sec = timed(lambda: hash_secret_raw(b"pw", b"somesalt", t, 16384, 1, 32, Type.ID), 7)
        rows_t.append((16384, t, 1, round(sec * 1000, 2)))
    write_csv("exp1_passes.csv", ["m_kib", "t", "p", "time_ms"], rows_t)

    cores = os.cpu_count() or 1
    rows_p = []
    for p in [1, 2, 4, 8]:
        sec = timed(lambda: hash_secret_raw(b"pw", b"somesalt", 3, 65536, p, 32, Type.ID), 3)
        rows_p.append((65536, 3, p, round(sec * 1000, 2), cores))
    write_csv("exp1_lanes.csv", ["m_kib", "t", "p", "time_ms", "cpu_cores"], rows_p)
    return rows_m, rows_t, rows_p


# ---------------------------------------------------------------------------
# Experiment 2: per-guess cost vs PBKDF2 and bcrypt
# ---------------------------------------------------------------------------

def exp2_per_guess(quick):
    """
    Settings follow the OWASP Password Storage Cheat Sheet recommendations
    (PBKDF2-HMAC-SHA256 600,000 iterations; bcrypt cost 10 minimum;
    Argon2id m=19 MiB, t=2, p=1). Memory per guess is what each scheme forces
    an attacker to hold for one guess in flight.
    """
    print("Experiment 2: per-guess cost vs PBKDF2 and bcrypt")
    reps = 3 if quick else 5
    pw, salt = b"correct horse", os.urandom(16)
    schemes = [
        ("PBKDF2-SHA256 (600k iter)",
         lambda: hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000), 0.2),
        ("bcrypt (cost 10)",
         lambda: bcrypt.hashpw(pw, bcrypt.gensalt(10)), 4.0),
        ("Argon2id (19 MiB, t=2)",
         lambda: hash_secret_raw(pw, salt, 2, 19 * 1024, 1, 32, Type.ID), 19 * 1024),
        ("Argon2id (64 MiB, t=3)",
         lambda: hash_secret_raw(pw, salt, 3, 64 * 1024, 1, 32, Type.ID), 64 * 1024),
    ]
    rows = []
    for name, fn, mem_kib in schemes:
        sec = timed(fn, reps)
        # Illustrative: how many guesses fit in parallel in 24 GiB of GPU memory
        # if memory were the only limit (arithmetic, not a measurement).
        parallel = int(24 * 1024 * 1024 / mem_kib)
        rows.append((name, round(sec * 1000, 1), mem_kib, parallel))
    write_csv("exp2_per_guess.csv",
              ["scheme", "time_ms", "memory_per_guess_kib",
               "max_parallel_guesses_in_24GiB"], rows)
    return rows


# ---------------------------------------------------------------------------
# Experiment 3: exact work of our implementation
# ---------------------------------------------------------------------------

def exp3_g_calls(quick):
    print("Experiment 3: G-call counts of the pure-Python implementation")
    rows = []
    mems = [64, 256, 1024] if quick else [64, 256, 1024, 4096]
    for y in (ARGON2D, ARGON2I, ARGON2ID):
        for m in mems:
            for t in (1, 3):
                argon2_impl.G_CALLS = 0
                t0 = time.perf_counter()
                argon2_hash(b"pw", b"somesalt", time_cost=t, memory_kib=m,
                            parallelism=1, type_=y)
                sec = time.perf_counter() - t0
                rows.append((argon2_impl.TYPE_NAMES[y], m, t, argon2_impl.G_CALLS,
                             t * m - 2, round(sec, 3)))
    write_csv("exp3_g_calls.csv",
              ["type", "m_kib", "t", "g_calls", "memory_block_calls_t_m_minus_2",
               "python_seconds"], rows)
    return rows


# ---------------------------------------------------------------------------
# Experiment 4: tradeoff attack
# ---------------------------------------------------------------------------

def dependency_graph(n_blocks, type_):
    """Run 1-pass, 1-lane Argon2 and return ref[j] = column that block j used."""
    trace = {}
    argon2_hash(b"password", b"somesalt", time_cost=1, memory_kib=n_blocks,
                parallelism=1, type_=type_, trace=trace)
    ref = [None] * trace["lane_len"]
    for (_, _, col, prev_col, _, ref_col) in trace["deps"]:
        assert prev_col == col - 1
        ref[col] = ref_col
    return ref


def attack_cost(ref, stored):
    """
    The attacker computes the pass left to right but keeps only the blocks in
    `stored` (plus the block it just computed). Whenever a needed block was not
    kept, it is recomputed from the nearest stored ancestors, recursively, with
    no extra memory (so shared work is recomputed each time).

    cost[j]  = G calls needed to rebuild block j from stored blocks
    depth[j] = length of the longest chain of G calls in that rebuild
               (the latency if the attacker had unlimited parallel cores)

    Returns (C, D): total computation and total latency, each relative to the
    honest computation of n blocks. These match the C(alpha) and D(alpha)
    definitions in Section II of the paper.
    """
    n = len(ref)
    cost = [1] * n
    depth = [1] * n
    for j in range(2, n):
        c, d = 1, 0
        if (j - 1) not in stored:
            c += cost[j - 1]
            d = max(d, depth[j - 1])
        r = ref[j]
        if r not in stored:
            c += cost[r]
            d = max(d, depth[r])
        cost[j] = c
        depth[j] = 1 + d

    total, latency = 2, 2
    for j in range(2, n):
        total += 1
        latency += 1
        r = ref[j]
        if r != j - 1 and r not in stored:     # j-1 is always in a register
            total += cost[r]
            latency += depth[r]
    return total / n, latency / n


def store_hybrid(ref, keep, frac_uniform):
    """
    Attacker's choice of which `keep` blocks to store.

    frac_uniform of the budget goes to evenly spaced blocks (this bounds how
    far back any rebuild has to walk along the prev-chain); the rest goes to
    the blocks referenced most often by later blocks (losing those would be
    the most costly). frac_uniform = 1.0 is the plain "store every k-th block"
    attacker. This is a simplified cousin of the paper's ranking attack.
    """
    n = len(ref)
    n_uniform = int(keep * frac_uniform)
    stored = {int(i * n / n_uniform) for i in range(n_uniform)} if n_uniform else set()
    stored |= {0, 1}

    counts = [0] * n
    for j in range(2, n):
        counts[ref[j]] += 1
    for i in sorted(range(n), key=lambda i: counts[i], reverse=True):
        if len(stored) >= keep:
            break
        stored.add(i)
    return stored


PAPER_TABLE_I = {  # 1-pass Argon2d, ranking tradeoff attack (paper, Table I)
    "1/2": (1.5, 1.5), "1/3": (4, 2.8), "1/4": (20.2, 5.5),
    "1/5": (344, 10.3), "1/6": (4660, 17), "1/7": (2 ** 18, 27),
}


def exp4_tradeoff(quick):
    print("Experiment 4: time-memory tradeoff attack on 1-pass Argon2d")
    n = 4096 if quick else 16384
    ref = dependency_graph(n, ARGON2D)
    rows = []
    for k in range(2, 8):
        keep = n // k
        paper_c, paper_d = PAPER_TABLE_I[f"1/{k}"]

        # Attacker A: store every k-th block.
        c, d = attack_cost(ref, store_hybrid(ref, keep, 1.0))
        rows.append((f"1/{k}", "uniform", "1.0", n, f"{c:.4g}", f"{d:.4g}",
                     paper_c, paper_d))

        # Attacker B: best uniform/most-referenced mix (swept, lowest C wins).
        best = min((attack_cost(ref, store_hybrid(ref, keep, f)), f)
                   for f in [x / 10 for x in range(1, 10)])
        (c, d), f = best
        rows.append((f"1/{k}", "hybrid", f"{f:.1f}", n, f"{c:.4g}", f"{d:.4g}",
                     paper_c, paper_d))
    write_csv("exp4_tradeoff.csv",
              ["memory_fraction", "strategy", "uniform_share", "blocks",
               "our_C", "our_D", "paper_C", "paper_D"], rows)
    return rows


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def _style(ax, title, xlabel, ylabel):
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=10)
    ax.set_xlabel(xlabel, color=INK2)
    ax.set_ylabel(ylabel, color=INK2)
    ax.tick_params(colors=INK2)
    ax.grid(True, color="#e6e5e0", linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#c9c8c2")


def make_charts(r1, r2, r4):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(FIGURES, exist_ok=True)

    def save(fig, name):
        fig.patch.set_facecolor(SURFACE)
        fig.tight_layout()
        path = os.path.join(FIGURES, name)
        fig.savefig(path, dpi=200)
        plt.close(fig)
        print(f"  wrote {os.path.relpath(path, HERE)}")

    rows_m, rows_t, rows_p = r1

    # 1a. time and memory vs m (two separate panels, never a dual axis)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4))
    ms = [r[0] / 1024 for r in rows_m]
    a1.plot(ms, [r[3] for r in rows_m], color=COLORS[0], lw=2, marker="o", ms=6)
    _style(a1, "Hashing time grows linearly with m", "memory m (MiB)", "time (ms)")
    a2.plot(ms, [r[4] / 1024 for r in rows_m], color=COLORS[0], lw=2, marker="o", ms=6,
            label="measured peak RSS")
    a2.plot(ms, ms, color=INK2, lw=1, ls="--", label="m (ideal)")
    _style(a2, "Peak memory equals m", "memory m (MiB)", "peak memory (MiB)")
    a2.legend(frameon=False)
    for a in (a1, a2):
        a.set_xticks(ms[-3:])          # linear axis, so linear growth looks linear
    save(fig, "exp1_memory.png")

    # 1b. time vs t and vs p
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4))
    a1.plot([r[1] for r in rows_t], [r[3] for r in rows_t], color=COLORS[0], lw=2,
            marker="o", ms=6)
    _style(a1, "Time grows linearly with passes t (m = 16 MiB)", "passes t", "time (ms)")
    a2.bar([str(r[2]) for r in rows_p], [r[3] for r in rows_p], color=COLORS[0], width=0.55)
    _style(a2, f"Lanes p use parallel cores ({rows_p[0][4]} cores, m = 64 MiB)",
           "lanes p", "time (ms)")
    save(fig, "exp1_passes_lanes.png")

    # 2. memory per guess (log scale), labels on bars
    fig, ax = plt.subplots(figsize=(10, 4))
    names = [r[0] for r in r2]
    mem = [r[2] for r in r2]
    bars = ax.barh(names, mem, color=COLORS[0], height=0.55)
    ax.set_xscale("log")
    for b, r in zip(bars, r2):
        ax.text(b.get_width() * 1.15, b.get_y() + b.get_height() / 2,
                f"{r[1]:.0f} ms/guess, {r[3]:,} guesses fit in 24 GiB",
                va="center", fontsize=9, color=INK2)
    ax.invert_yaxis()
    ax.set_xlim(0.1, max(mem) * 300)
    _style(ax, "Memory an attacker must hold per guess", "memory per guess (KiB, log scale)", "")
    save(fig, "exp2_per_guess.png")

    # 4. tradeoff penalty vs paper
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4))
    fr = [f"1/{k}" for k in range(2, 8)]
    labels = {"uniform": "ours: store every k-th block",
              "hybrid": "ours: best hybrid mix"}
    for i, strat in enumerate(("uniform", "hybrid")):
        sel = [r for r in r4 if r[1] == strat]
        a1.plot(fr, [float(r[4]) for r in sel], color=COLORS[i], lw=2, marker="o", ms=6,
                label=labels[strat])
        a2.plot(fr, [float(r[5]) for r in sel], color=COLORS[i], lw=2, marker="o", ms=6,
                label=labels[strat])
    a1.plot(fr, [PAPER_TABLE_I[f][0] for f in fr], color=INK2, lw=1.5, ls="--",
            marker="s", ms=6, label="paper Table I (ranking)")
    a2.plot(fr, [PAPER_TABLE_I[f][1] for f in fr], color=INK2, lw=1.5, ls="--",
            marker="s", ms=6, label="paper Table I (ranking)")
    a1.set_yscale("log")
    a2.set_yscale("log")
    _style(a1, "Computation penalty C(α)", "memory kept by attacker (α)", "x honest work")
    _style(a2, "Time penalty D(α), unlimited cores", "memory kept by attacker (α)",
           "x honest time")
    a1.legend(frameon=False, fontsize=8)
    save(fig, "exp4_tradeoff.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller, faster runs")
    args = ap.parse_args()
    r1 = exp1_scaling(args.quick)
    r2 = exp2_per_guess(args.quick)
    exp3_g_calls(args.quick)
    r4 = exp4_tradeoff(args.quick)
    make_charts(r1, r2, r4)
    print("Done. Results are in results/ and results/figures/.")


if __name__ == "__main__":
    main()
