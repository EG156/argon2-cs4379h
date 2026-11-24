# Code Guide: where each function comes from

This guide maps every function in the project to the part of the Argon2 paper
and of RFC 9106 that it implements, so you can read the code and the sources
side by side.

**Sources**

- **Paper**: A. Biryukov, D. Dinu, D. Khovratovich, "Argon2: New Generation of
  Memory-Hard Functions for Password Hashing and Other Applications," IEEE
  EuroS&P 2016. DOI [10.1109/EuroSP.2016.31](https://doi.org/10.1109/EuroSP.2016.31).
  Section numbers below are from this version (I. Introduction, II. Definitions,
  III. Specification, IV. Features, V. Security Analysis, VI. Design Rationale,
  VII. Performance, Appendix A. Permutation P).
- **RFC**: RFC 9106, "Argon2 Memory-Hard Function for Password Hashing and
  Proof-of-Work Applications," September 2021,
  <https://www.rfc-editor.org/rfc/rfc9106>. The paper explains *why*; the RFC
  pins down the exact bytes, so the code follows the RFC wherever byte order or
  encoding matters.

Line numbers are approximate and may shift as the code is edited.

---

## 1. Big picture

Argon2 fills a block of memory (m KiB, as 1 KiB blocks) with pseudo-random data
in a way that forces anyone computing it to actually hold that memory. The
password only enters at the start (through H0) and the tag only comes out at
the end, so all the work in between is "memory-hard."

```
password, salt, params
        │
        ▼
   compute_h0 ── 64-byte digest H0                    (RFC 3.2 step 1)
        │
        ▼
   h_prime(H0 ‖ 0 ‖ lane), h_prime(H0 ‖ 1 ‖ lane)     (RFC 3.2 steps 3-4)
        │      → first two blocks of every lane
        ▼
   for each pass, for each of 4 slices, for each lane:
       _fill_segment                                  (RFC 3.2 steps 5-6)
          ├─ pick J1, J2  (data-dependent or address block)   RFC 3.4.1
          ├─ _reference_index → which old block to mix in     RFC 3.4.2
          └─ G(previous block, reference block)               RFC 3.5
        │
        ▼
   XOR last column → h_prime → tag                    (RFC 3.2 steps 7-8)
```

Memory layout: `B[lane][column]`. There are `p` lanes (rows). Each lane has
`q = m'/p` columns, cut into 4 slices of `q/4` columns. One lane × one slice is
a **segment**, the unit of work `_fill_segment` does.

---

## 2. `argon2_impl.py`: the algorithm

### Constants (top of file)

| Name | Value | Source |
|---|---|---|
| `ARGON2D, ARGON2I, ARGON2ID` | 0, 1, 2 | Type `y`, RFC 3.1 |
| `VERSION` | `0x13` | Version 1.3, RFC 3.1 |
| `BLOCK_WORDS` | 128 | 1024-byte block = 128 × 64-bit words, paper III-B, RFC 3.2 |
| `SYNC_POINTS` | 4 | 4 slices per lane, paper III-B, RFC 3.2 |
| `G_CALLS` | counter | Not in the spec. Counts G calls for Experiment 3. |

### Helpers

| Function | Line | What it does | Paper | RFC |
|---|---|---|---|---|
| `le32(n)` | ~33 | 4-byte little-endian encoding | | §2 notation (LE32) |
| `blake2b(data, outlen)` | ~42 | BLAKE2b with chosen output length; this is H | III | §3.2, [RFC 7693] |
| `bytes_to_block`, `block_to_bytes` | ~161 | 1024 bytes ↔ 128 little-endian words | | §3.2, §3.5 |

### `h_prime(data, outlen)`: variable-length hash H' (~line 47)

- **Paper**: Section III (H' is defined alongside the operation).
- **RFC**: §3.3.
- **How it works**: if `outlen ≤ 64`, one BLAKE2b call on `LE32(outlen) ‖ data`.
  Otherwise, chain BLAKE2b-512 calls (`V1 = H(LE32(T) ‖ X)`, `V2 = H(V1)`, ...),
  keep the first 32 bytes of each, and end with one final digest that supplies
  the remaining bytes. `r = ceil(T/32) - 2` is the number of full 64-byte calls.
- **Used for**: the first two 1024-byte blocks of every lane, and the final tag.
- **Tested by**: random cases with `tag_len` of 65, 100, and 128 bytes in
  `test_random_against_argon2_cffi` (these force the long branch).

### `compute_h0(...)`: pre-hashing digest H0 (~line 68)

- **Paper**: Section III-B (Operation).
- **RFC**: §3.2 step 1.
- **How it works**: hashes `p, T, m, t, v, y` and then each of password, salt,
  secret, associated data with a 4-byte length prefix. Output is 64 bytes.
  Because every input goes in here, changing any one of them changes every
  block of memory.
- **Tested by**: `test_h0_matches_rfc` (exact match with the "Pre-hashing
  digest" printed in RFC §5.1).

### `_gb(v, a, b, c, d)`: quarter-round GB (~line 87)

- **Paper**: Appendix A (Permutation P).
- **RFC**: §3.6.
- **How it works**: BLAKE2b's G mixing function on four 64-bit words, with one
  change: every `a + b` becomes `a + b + 2·lo32(a)·lo32(b)` (mod 2^64). The
  multiplication adds latency that custom hardware cannot easily shortcut
  (design reasoning in paper VI-C). Rotations
  are 32, 24, 16, 63 bits.

### `_permute(v, idx)`: permutation P (~line 115)

- **Paper**: Appendix A.
- **RFC**: §3.6.
- **How it works**: treats 16 words as a 4×4 matrix and applies `_gb` to the
  four columns, then the four diagonals (one BLAKE2b round).

### `_ROWS`, `_COLS` (~line 138)

The 1024-byte block is viewed as an 8×8 matrix of 16-byte registers (two words
each). `_ROWS[i]` lists the 16 word positions in row i; `_COLS[i]` lists the 16
word positions in column i. RFC §3.5.

### `G(x, y)`: compression function (~line 142)

- **Paper**: Section III-D (Compression function G), with P from Appendix A;
  design reasoning in VI-C.
- **RFC**: §3.5.
- **How it works**: `R = X ⊕ Y`; apply P to each row of R, then to each
  column, giving Z; return `Z ⊕ R`.
- **Counts**: increments `G_CALLS` (Experiment 3).

### `_reference_index(...)`: which block to mix in (~line 178)

- **Paper**: Section III-C (Indexing); why it favors recent blocks: VI-A.
- **RFC**: §3.4.2.
- **How it works**, in three steps (marked in the code):
  1. **Reference set size** `|R|` (`area`). On pass 0 only blocks already
     computed count. Blocks from *other* lanes are only allowed from finished
     slices, so lanes in the same slice never depend on each other and can run
     in parallel. The block right before the current one is left out because
     it is already one input to G.
  2. **Non-uniform map**: `x = J1²/2³²`, `y = |R|·x/2³²`, `zz = |R| − 1 − y`.
     This makes recent blocks more likely to be chosen.
  3. **Offset**: on later passes, R starts at the slice after the current one,
     wrapping around the lane.

### `argon2_hash(...)`: main entry point (~line 225)

- **Paper**: Section III-A (Inputs) and III-B (Operation).
- **RFC**: §3.1 (inputs) and §3.2 (steps 1-8, marked in the code).
- **Steps**:
  1. H0 (`compute_h0`).
  2. Round `m` down to `m' = 4p·floor(m/4p)`; lanes have `q = m'/p` columns,
     slices have `q/4`.
  3-4. `B[i][0] = H'(H0 ‖ LE32(0) ‖ LE32(i))`, `B[i][1] = H'(H0 ‖ LE32(1) ‖ LE32(i))`.
  5-6. For each pass, each slice, each lane: `_fill_segment`.
  7-8. `C = XOR of B[i][q−1]` over all lanes; tag = `H'^T(C)`.
- **Extra project options** (not in the spec):
  - `trace`: records `(pass, lane, col, prev_col, ref_lane, ref_col)` for every
    block, giving the dependency graph used in Experiment 4.
  - `pass_hook`: called after each pass with all blocks, so the tests can
    compare memory to RFC §5.1 after passes 0, 1, 2.

### `_fill_segment(...)`: fill one lane × one slice (~line 284)

- **Paper**: III-B (filling), III-C (where J1, J2 come from).
- **RFC**: §3.2 steps 5-6, §3.4.1.
- **How it works**, per block:
  1. **Get 64 random bits (J1 low half, J2 high half)**:
     - Argon2d (RFC §3.4.1.1): first word of the previous block. Depends on the
       password, so it is fastest and best against tradeoff attacks, but leaks
       timing through cache access patterns.
     - Argon2i (RFC §3.4.1.2): the next word of an **address block**,
       `G(0, G(0, Z))`, where Z holds `(pass, lane, slice, m', t, y, counter)`.
       Does not depend on the password, so it resists side channels.
       `next_addresses()` makes a new address block every 128 blocks.
     - Argon2id (RFC §3.4.1.3): Argon2i rule for the first half of pass 0
       (slices 0-1), Argon2d rule after that.
  2. **Reference lane** `= J2 mod p` (forced to the current lane in pass 0,
     slice 0), **reference column** from `_reference_index`.
  3. **New block** `= G(previous, reference)`. On passes after the first,
     version 1.3 XORs this into the old value instead of overwriting it.

### `argon2_hex(...)` (~line 350)

Same as `argon2_hash`, returns a hex string.

---

## 3. `test_argon2.py`: verification

| Test | What it checks | Source of truth |
|---|---|---|
| `test_rfc_vectors` | Final tags for Argon2d, Argon2i, Argon2id | RFC §5.1, §5.2, §5.3 |
| `test_h0_matches_rfc` | H0 digest | RFC §5.1 "Pre-hashing digest" |
| `test_intermediate_blocks_match_rfc` | Memory words after passes 0, 1, 2 | RFC §5.1 block dumps |
| `test_random_against_argon2_cffi` | 60 seeded random parameter sets, all three types, tag lengths 4 to 128 | argon2-cffi (reference C code) |

The component tests localize a bug: wrong H0 means the input encoding is off;
right H0 but wrong blocks after pass 0 means G or indexing is off; right pass 0
but wrong pass 1 means the XOR rule or the pass > 0 indexing is off.

---

## 4. `experiments.py`: reproducing the paper's claims

| Function | Purpose | Paper link |
|---|---|---|
| `write_csv`, `timed` | Save rows to `results/`; median wall-clock time | |
| `_PEAK_RSS_CHILD`, `peak_rss_kib` | Peak memory of one hash, measured in a fresh child process (Windows: psutil peak working set; macOS: `ru_maxrss` in bytes; Linux: `VmHWM`) | |
| `exp1_scaling` | Time and peak memory vs m; time vs t; time vs p | III-A (parameters), VII (performance) |
| `exp2_per_guess` | Per-guess time and memory of PBKDF2, bcrypt, Argon2id at OWASP settings | I, II-A (why memory-hardness matters) |
| `exp3_g_calls` | Exact G-call count = t·m − 2 (+2 per address block for i/id) | III-B, III-C |
| `dependency_graph` | Runs 1-pass Argon2d with `trace` and returns `ref[j]` | III-C |
| `attack_cost` | Given which blocks an attacker kept, computes C(α) (extra computation) and D(α) (latency with unlimited cores) | II-A (definitions) |
| `store_hybrid` | Attacker strategy: part evenly spaced blocks, part most-referenced blocks | simplified version of V-A (ranking attack) |
| `PAPER_TABLE_I` | The paper's numbers for comparison (C(1/7) = 2¹⁸) | V-A, Table I |
| `exp4_tradeoff` | Runs both attacker strategies at α = 1/2 to 1/7 | V-A, Table I |
| `_style`, `make_charts` | Draw the four PNGs in `results/figures/` | |
| `main` | Runs everything (`--quick` for smaller sizes) | |

---

## 5. `demo.py`: presentation demo

Run `python demo.py` for a menu, `python demo.py all` for every section, or
`python demo.py N` for one section.

| Section / function | What it shows | Paper / RFC link |
|---|---|---|
| 1 `section_correctness`, `compare`, `bits_changed` | Our tags equal argon2-cffi's for Argon2id/d/i; one-bit password change flips about half the tag bits; RFC vectors, H0 and intermediate blocks match | RFC §5 |
| 2 `section_bruteforce` | Cracks a 4-digit PIN stored with salted SHA-256 in milliseconds; the same attack on Argon2id (OWASP settings) manages about 50 guesses per second | paper I, II-A (motivation) |
| 3 `section_memory` | Peak RAM of one Argon2id hash at m = 64 MiB, 256 MiB, 1 GiB (uses `experiments.peak_rss_kib`) | paper III-A, VII |
| 4 `section_side_channel`, `reference_columns` | Reference block numbers for two passwords: different under Argon2d, identical under Argon2i | paper III-C; RFC §3.4.1 |
| 5 `section_tradeoff` | Attacker keeps 1/k of memory; computation penalty C next to paper Table I (uses Experiment 4 functions) | paper II-A, V-A, Table I |
| 6 `section_storage` | `$argon2id$v=19$m=...` string format; verify right and wrong password; fresh salt each time | RFC §4 (parameters) |
| 7 `section_charts`, `open_file` | Opens the four experiment charts with the OS viewer | |
| `heading`, `pause`, `menu`, `run`, `run_all`, `main` | Output formatting, Enter-to-continue, menu and argument handling | |
