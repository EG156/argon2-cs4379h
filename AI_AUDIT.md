# AI_AUDIT: Team AI Verification Log

CS 4379H Cryptography, Fall 2026

- **Team:** Caleb Tyler, Matthew Tidwell, Brendan O'Mara
- **Paper:** A. Biryukov, D. Dinu, D. Khovratovich, "Argon2: New Generation of
  Memory-Hard Functions for Password Hashing and Other Applications," IEEE
  EuroS&P 2016
- **AI assistant(s) used:** Claude (Claude Opus 5.5), via claude.ai

## How to use this log

AI use in this project is required, not banned. Every AI output the team relies
on (a claim we repeat, a citation we include, code we commit, an idea we adopt)
appears here as one row, whether or not it turned out to be correct. Throwaway
drafts we discarded are not logged. This log lives in the root of the repo and
is updated as we work; the commit history shows it growing.

## Categories

| Code | Category |
|---|---|
| FC | Fabricated citation (paper, author, or venue that does not exist or does not say what was claimed) |
| NA | Nonexistent API or function (library, method, flag, or parameter that does not exist) |
| MR | Misstated result (real source, but the number, finding, or claim is wrong) |
| CW | Code runs but is wrong (executes without error, output is incorrect) |
| OC | Overclaim (true in a narrow case, stated as general) |
| OK | Verified correct (the output survived verification) |

## Roles

| Role | What it covers in this project |
|---|---|
| Reviewer | Task 1: paper overview and the AI Review Disagreement Table (checking AI claims about what the paper says) |
| Student Researcher | Task 2: topic choice and the AI Idea Appendix |
| Reproducibility Checker | Task 3: the code, the verification plan, and this AI_AUDIT log |
| Archaeologist | Verifying the two README references (prior work Argon2 builds on, later work that builds on Argon2) |
| Quanta Correspondent | Plain-language explanation of Argon2 for a general audience *(to be confirmed on Canvas)* |

## Log

Role is one of: Reviewer, Archaeologist, Student Researcher, Reproducibility Checker, Quanta Correspondent.

| # | Date | Role | What the AI claimed or produced | Category | Verified? | How we checked it | Team member |
|---|---|---|---|---|---|---|---|
| 1 | 2026-11-18 | Reproducibility Checker | Pure-Python Argon2d/i/id (`argon2_impl.py`) following RFC 9106 | OK | Yes | All 3 RFC 9106 §5 test vectors pass (`test_rfc_vectors`) | Matthew Tidwell |
| 2 | 2026-11-18 | Reproducibility Checker | H0 and memory blocks after passes 0, 1, 2 match RFC 9106 §5.1 | OK | Yes | Compared against the hex values printed in the RFC text (`test_h0_matches_rfc`, `test_intermediate_blocks_match_rfc`) | Matthew Tidwell |
| 3 | 2026-11-24 | Reproducibility Checker | Implementation matches the reference C implementation for any parameters | OK | Yes | 60 random cases vs argon2-cffi, all three types, tag lengths 4-128 bytes (`test_random_against_argon2_cffi`) | Matthew Tidwell |
| 4 | 2026-11-18 | Reproducibility Checker | Peak-memory code treated macOS `ru_maxrss` as KiB | CW | Yes (caught) | Read the macOS `getrusage` man page: macOS reports bytes, Linux reports KiB. Fixed by dividing by 1024 on macOS | Matthew Tidwell |
| 5 | 2026-11-18 | Reproducibility Checker | Measuring peak memory with `ru_maxrss` in a child process on Linux | CW | Yes (caught) | Peak memory read 0 for every m. On Linux a child inherits the parent's `ru_maxrss`. Fixed by reading `VmHWM` from `/proc/self/status` and measuring before the timing runs | Matthew Tidwell |
| 6 | 2026-11-18 | Reproducibility Checker | First tradeoff attacker ("store the most-referenced blocks") for Experiment 4 | CW | Yes (caught) | Penalties came out absurd (C up to about 10³², far above the paper's Table I). Replaced with the hybrid attacker (evenly spaced + most-referenced), which matches Table I at α = 1/2 and 1/3 | Matthew Tidwell |
| 7 | 2026-11-18 | Reviewer | AI's reading of the paper PDF gave Table I C(1/7) = "218" | MR | Yes (caught) | 218 is smaller than C(1/6) = 4660, which makes no sense for a penalty that grows as memory shrinks. The superscript was lost in text extraction; the real value is 2¹⁸ = 262,144. Re-checked 2026-11-24: an online text extraction of the paper shows the same "218" error | Matthew Tidwell |
| 8 | 2026-11-24 | Reproducibility Checker | Code comment: indexing is in paper Section III-B | MR | Yes (caught) | Paper's table of contents: III-B is Operation, III-C is Indexing, III-D is Compression function G. Comment fixed to III-C | Matthew Tidwell |
| 9 | 2026-11-24 | Reproducibility Checker | `experiments.py` docstring: full run takes "2 to 4 minutes" | MR | Yes (caught) | Timed it: about 30 s full, about 11 s with `--quick`. Docstring fixed | Matthew Tidwell |
| 10 | 2026-11-24 | Reproducibility Checker | Random test cases described as reproducible, but passwords and salts used `os.urandom` | OC | Yes (caught) | Only the parameters were seeded; the byte inputs changed every run. Switched to `rng.randbytes` so all 60 cases are identical each run | Matthew Tidwell |
| 11 | 2026-11-24 | Reproducibility Checker | README draft: pure Python is "about 100 times slower" than the C library | OC | Partially | `demo.py` timings ranged from about 25x to about 140x depending on variant and warm-up. README changed to "roughly 25 to 150 times" | Matthew Tidwell |
| 12 | 2026-11-24 | Reproducibility Checker | Experiment 3: Argon2i/id use 2 extra G calls per address block | OK | Yes | From `exp3_g_calls.csv`: Argon2i, m = 64, t = 1 gives 70 calls vs 62 = t·m − 2; the 8 extra = 4 segments × 1 address block × 2 G calls | Matthew Tidwell |
| 13 | 2026-11-24 | Reproducibility Checker | OWASP settings used in Experiment 2: Argon2id m = 19 MiB, t = 2, p = 1; bcrypt cost 10; PBKDF2-SHA256 600,000 iterations | OK | Yes | Checked against the current OWASP Password Storage Cheat Sheet | Matthew Tidwell |
| 14 | 2026-11-24 | Archaeologist | Prior work: Percival, "Stronger Key Derivation via Sequential Memory-Hard Functions," BSDCan 2009 | OK | Yes | PDF at tarsnap.com/scrypt/scrypt.pdf has this title and author; BSDCan 2009 schedule lists Percival's scrypt talk; the Argon2 paper cites scrypt | Matthew Tidwell |
| 15 | 2026-11-24 | Archaeologist | Later work: Alwen & Blocki, "Efficiently Computing Data-Independent Memory-Hard Functions," CRYPTO 2016, LNCS 9815, pp. 241-271, DOI 10.1007/978-3-662-53008-5_9, attacks Argon2i | OK | Yes | DOI resolves to Springer; IACR ePrint 2016/115 abstract names Argon2i; RFC 9106 reference [AB16] gives the same DOI | Matthew Tidwell |
| 16 | 2026-11-24 | Archaeologist | Argon2 paper DOI is 10.1109/EuroSP.2016.31 | OK | Yes | DOI redirects to IEEE Xplore; RFC 9106 reference [ARGON2ESP] gives the same DOI | Matthew Tidwell |
| 17 | 2026-11-24 | Reproducibility Checker | Function-to-section mapping in `CODE_GUIDE.md` (H0 and operation III-B, indexing III-C, G III-D, P Appendix A, C(α)/D(α) II-A, Table I V-A; RFC §3.2-3.6) | OK | Yes | Paper's section headings and RFC 9106 table of contents. Unverifiable RFC figure numbers were removed rather than guessed | Matthew Tidwell |
| 18 | 2026-10-05 | Reviewer | AI review of the paper: high memory use could make servers more vulnerable to denial of service | OK | Yes | Judged right: the defender pays the same memory cost per login as the attacker pays per guess, so many login requests at once can exhaust server RAM (recorded in the proposal's AI Review Disagreement Table) | Matthew Tidwell |
| 19 | 2026-10-05 | Reviewer | AI review: the paper's evidence for ASIC resistance is too limited | OC | Partially | Judged shallow: a custom ASIC is possible, but it still needs the full memory per guess, and memory is the expensive part. Experiment 2 and the tradeoff attack (Experiment 4) support this | Matthew Tidwell |
| 20 | 2026-10-05 | Reviewer | AI review: Argon2's parameter flexibility could become a weakness | OC | No | Judged wrong as stated: low settings weaken it, but even weak settings beat a fast hash, and RFC 9106 Section 4 and OWASP give recommended minimums. True only for misconfigured deployments | Matthew Tidwell |
| 21 | 2026-10-05 | Student Researcher | AI Idea 1: implement Argon2 from the spec, verify against the reference, benchmark m/t/p, simulate a tradeoff attack | OK | Yes | Labeled feasible and adopted as our topic. Confirmed by doing it: RFC vectors pass, experiments run on a laptop in about 30 s | Matthew Tidwell |
| 22 | 2026-10-05 | Student Researcher | AI Idea 2: benchmark GPU cracking speed of Argon2 vs bcrypt, scrypt, PBKDF2 | OK | Yes | Accurate idea but labeled already published: cracking-tool benchmarks and the PHC benchmarks the paper cites cover it. Rejected for novelty, not for being wrong | Matthew Tidwell |
| 23 | 2026-10-05 | Student Researcher | AI Idea 3: use Argon2d to hash passwords on a shared cloud server because it is faster and more tradeoff-resistant | OC | No | Labeled technically flawed: Argon2d's data-dependent memory access leaks timing to anyone sharing the hardware; the paper recommends Argon2i where attackers can reach the machine. Demo section 4 shows the leak | Matthew Tidwell |
| 24 | | Quanta Correspondent | *(to add: plain-language explanation used in slides)* | | | | |

## End-of-semester summary (fill in before the final demo)

- Total AI outputs logged: **23**    Verified correct: **12**    Failed verification: **11**
  (failed = rows 4-11, 19, 20, 23: 3 CW, 3 MR, 5 OC; no fabricated citations or nonexistent APIs found)
- The two most consequential AI failures (for Task 6, lessons learned):
  - Failure 1: **Row 7 (MR).** The AI's reading of the paper gave Table I's C(1/7) as 218 instead of 2¹⁸ = 262,144, because the PDF text extraction dropped the superscript. Our whole tradeoff comparison is measured against Table I, so this would have made our attacker look over a million times worse than the paper's at α = 1/7, when the real gap is about 1,000 times. Caught because 218 is smaller than the previous entry (4,660), which is impossible for a penalty that grows as memory shrinks.
  - Failure 2: **Row 5 (CW).** Peak-memory code that ran without errors and reported 0 MiB on Linux, because a child process inherits its parent's `ru_maxrss`. Experiment 1's main claim (peak memory equals m) depends on this number. Caught because a memory-hard function using 0 bytes is impossible; fixed by reading `VmHWM` and measuring before any large hash runs.
- Which verification habit saved your team the most time? **Checking every output against an independent reference before building on it:** the RFC 9106 test vectors and intermediate blocks for the code, argon2-cffi for random inputs, and the paper's own numbers for the experiments. The intermediate-block vectors pointed to the exact function at fault whenever something broke.
