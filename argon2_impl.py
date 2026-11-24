"""
Pure-Python Argon2 (Argon2d, Argon2i, Argon2id), version 0x13.

Written from the Argon2 paper (Biryukov, Dinu, Khovratovich, EuroS&P 2016),
Section III (Specification) and Appendix A (Permutation P), with the exact
byte-level details taken from RFC 9106 Section 3 so the output can be checked
against standard libraries (argon2-cffi). See CODE_GUIDE.md for a
function-by-function map to the paper and the RFC.

This is a teaching / research implementation: it is readable, not fast, and it
must NOT be used to protect real passwords.

Extra feature for the project: `argon2_hash(..., trace=...)` can record, for
every block, which earlier blocks it was computed from. The tradeoff-attack
experiment uses this dependency graph.
"""

import hashlib
import struct

ARGON2D, ARGON2I, ARGON2ID = 0, 1, 2
TYPE_NAMES = {ARGON2D: "argon2d", ARGON2I: "argon2i", ARGON2ID: "argon2id"}
VERSION = 0x13
BLOCK_WORDS = 128          # a block is 1024 bytes = 128 x 64-bit words
SYNC_POINTS = 4            # each lane is split into 4 slices
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF

# Global counter of compression-function calls (used by Experiment 3).
G_CALLS = 0


def le32(n):
    """Encode n as a 4-byte little-endian integer (RFC 9106 notation LE32)."""
    return struct.pack("<I", n)


# ---------------------------------------------------------------------------
# H0 and the variable-length hash H'   (RFC 9106 Sections 3.2 and 3.3)
# ---------------------------------------------------------------------------

def blake2b(data, outlen):
    """BLAKE2b with an `outlen`-byte digest (1..64). This is the hash H."""
    return hashlib.blake2b(data, digest_size=outlen).digest()


def h_prime(data, outlen):
    """
    Variable-length hash H'^T built from BLAKE2b (RFC 9106 Section 3.3).

    For outputs of at most 64 bytes this is a single BLAKE2b call. For longer
    outputs (the 1024-byte first blocks, or long tags) it chains BLAKE2b calls
    and keeps the first 32 bytes of each, then appends one final digest that
    supplies the remaining bytes.
    """
    if outlen <= 64:
        return blake2b(le32(outlen) + data, outlen)
    r = (outlen + 31) // 32 - 2          # number of full 64-byte digests
    v = blake2b(le32(outlen) + data, 64)
    out = [v[:32]]
    for _ in range(r - 1):
        v = blake2b(v, 64)
        out.append(v[:32])
    out.append(blake2b(v, outlen - 32 * r))
    return b"".join(out)


def compute_h0(password, salt, secret, ad, p, tag_len, m, t, y):
    """
    Pre-hashing digest H0 (paper Section III-B, RFC 9106 Section 3.2 step 1).

    Every parameter and input is length-prefixed and hashed into one 64-byte
    value, so changing any of them changes every memory block.
    """
    data = (le32(p) + le32(tag_len) + le32(m) + le32(t) + le32(VERSION) + le32(y)
            + le32(len(password)) + password
            + le32(len(salt)) + salt
            + le32(len(secret)) + secret
            + le32(len(ad)) + ad)
    return blake2b(data, 64)


# ---------------------------------------------------------------------------
# Compression function G   (paper Appendix A, RFC 9106 Sections 3.5 and 3.6)
# ---------------------------------------------------------------------------

def _gb(v, a, b, c, d):
    """
    Quarter-round GB on words a, b, c, d of v (RFC 9106 Section 3.6).

    Same as BLAKE2b's G function, except each addition x + y is replaced by
    x + y + 2 * lo32(x) * lo32(y) (the "BlaMka" change). The multiplication
    makes the function harder to speed up on ASICs. Rotations are 32, 24,
    16, 63 bits, as in BLAKE2b. All arithmetic is mod 2^64.
    """
    va, vb, vc, vd = v[a], v[b], v[c], v[d]

    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd ^= va
    vd = ((vd >> 32) | (vd << 32)) & MASK64
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb ^= vc
    vb = ((vb >> 24) | (vb << 40)) & MASK64

    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd ^= va
    vd = ((vd >> 16) | (vd << 48)) & MASK64
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb ^= vc
    vb = ((vb >> 63) | (vb << 1)) & MASK64

    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _permute(v, idx):
    """
    Permutation P (paper Appendix A, RFC 9106 Section 3.6) applied in place
    to the 16 words of v at positions idx (eight 16-byte registers).

    One BLAKE2b round: GB on the four columns, then on the four diagonals.
    """
    i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15 = idx
    _gb(v, i0, i4, i8, i12)
    _gb(v, i1, i5, i9, i13)
    _gb(v, i2, i6, i10, i14)
    _gb(v, i3, i7, i11, i15)
    _gb(v, i0, i5, i10, i15)
    _gb(v, i1, i6, i11, i12)
    _gb(v, i2, i7, i8, i13)
    _gb(v, i3, i4, i9, i14)


# The 1024-byte block is viewed as an 8x8 matrix of 16-byte registers
# (each register = 2 words). P is applied first to each row, then to each
# column (paper Section III-D, RFC 9106 Section 3.5).
# _ROWS[i]: the 16 word positions in row i.
# _COLS[i]: the 16 word positions in column i (2 words from each of 8 rows).
_ROWS = [list(range(16 * i, 16 * i + 16)) for i in range(8)]
_COLS = [[16 * r + 2 * i + k for r in range(8) for k in (0, 1)] for i in range(8)]


def G(x, y):
    """
    Compression function G (paper Section III-D, RFC 9106 Section 3.5).

    x, y : blocks (lists of 128 64-bit words)
    R = X xor Y; apply P to every row of R, then to every column, giving Z;
    return Z xor R.
    """
    global G_CALLS
    G_CALLS += 1
    r = [a ^ b for a, b in zip(x, y)]
    q = r[:]
    for idx in _ROWS:
        _permute(q, idx)
    for idx in _COLS:
        _permute(q, idx)
    return [a ^ b for a, b in zip(q, r)]


def bytes_to_block(b):
    """1024 bytes -> list of 128 little-endian 64-bit words."""
    return list(struct.unpack("<128Q", b))


def block_to_bytes(block):
    """List of 128 64-bit words -> 1024 bytes (inverse of bytes_to_block)."""
    return struct.pack("<128Q", *block)


ZERO_BLOCK = [0] * BLOCK_WORDS


# ---------------------------------------------------------------------------
# Indexing   (paper Section III-C, RFC 9106 Section 3.4)
# ---------------------------------------------------------------------------

def _reference_index(pass_n, slc, index, same_lane, j1, seg_len, lane_len):
    """
    Map the 32-bit value J1 to a block column inside the chosen lane
    (paper Section III-C, RFC 9106 Section 3.4.2).

    pass_n, slc, index : where the new block is (pass, slice, index in segment)
    same_lane          : True if the reference lane is the current lane
    Returns the column z of the reference block B[l][z].

    Step 1: `area` = number of blocks that may be referenced (the set R).
            On the first pass only blocks already computed count. Blocks in
            other lanes are only allowed from finished slices, so lanes can be
            filled in parallel within a slice.
    Step 2: the non-uniform map x = J1^2 / 2^32, y = |R| * x / 2^32,
            zz = |R| - 1 - y. It favors recent blocks.
    Step 3: offset zz from the start of R (the slice after the current one
            on later passes) and wrap around the lane.
    """
    if pass_n == 0:
        if slc == 0:
            area = index - 1
        elif same_lane:
            area = slc * seg_len + index - 1
        else:
            area = slc * seg_len + (-1 if index == 0 else 0)
    else:
        if same_lane:
            area = lane_len - seg_len + index - 1
        else:
            area = lane_len - seg_len + (-1 if index == 0 else 0)

    # Step 2: non-uniform mapping that favors recent blocks.
    x = (j1 * j1) >> 32
    yv = (area * x) >> 32
    rel = area - 1 - yv

    # Step 3: R starts right after the current slice (or at 0 on pass 0).
    start = 0
    if pass_n != 0:
        start = 0 if slc == SYNC_POINTS - 1 else (slc + 1) * seg_len
    return (start + rel) % lane_len


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def argon2_hash(password, salt, *, time_cost, memory_kib, parallelism,
                tag_len=32, type_=ARGON2ID, secret=b"", ad=b"", trace=None,
                pass_hook=None):
    """
    Compute an Argon2 tag.

    password, salt, secret, ad : bytes
    time_cost   : t, number of passes
    memory_kib  : m, memory size in KiB (1 block = 1 KiB)
    parallelism : p, number of lanes
    tag_len     : T, output length in bytes (4 or more)
    type_       : ARGON2D, ARGON2I, or ARGON2ID (y in the paper)
    trace       : optional dict; if given, it is filled with the dependency
                  graph (see the tradeoff-attack experiment).
    pass_hook   : optional function(pass_n, blocks) called after each pass
                  with all memory blocks; the tests use it to compare
                  intermediate blocks against RFC 9106 Section 5.1.

    Follows the 8 steps of RFC 9106 Section 3.2 (paper Section III-B).
    Returns the tag as bytes.
    """
    p, t, m, y = parallelism, time_cost, memory_kib, type_
    if m < 8 * p:
        raise ValueError("memory_kib must be at least 8 * parallelism")

    # Step 1: H0.
    h0 = compute_h0(password, salt, secret, ad, p, tag_len, m, t, y)

    # Step 2: allocate m' blocks as p lanes (rows) of q columns, 4 slices each.
    m_prime = 4 * p * (m // (4 * p))     # round down to a multiple of 4p
    lane_len = m_prime // p              # q columns
    seg_len = lane_len // SYNC_POINTS

    B = [[None] * lane_len for _ in range(p)]
    if trace is not None:
        trace.update(p=p, t=t, lane_len=lane_len, seg_len=seg_len, deps=[])

    # Steps 3-4: first two blocks of every lane come from H0 via H'.
    for lane in range(p):
        B[lane][0] = bytes_to_block(h_prime(h0 + le32(0) + le32(lane), 1024))
        B[lane][1] = bytes_to_block(h_prime(h0 + le32(1) + le32(lane), 1024))

    # Steps 5-6: fill memory, slice by slice, for t passes.
    for pass_n in range(t):
        for slc in range(SYNC_POINTS):
            # Lanes inside one slice are independent (could run in parallel).
            for lane in range(p):
                _fill_segment(B, pass_n, slc, lane, p, t, y, m_prime,
                              lane_len, seg_len, trace)
        if pass_hook is not None:              # used by the unit tests
            pass_hook(pass_n, [blk for lane_blocks in B for blk in lane_blocks])

    # Steps 7-8: final block C = XOR of the last column, then tag = H'^T(C).
    c = B[0][lane_len - 1][:]
    for lane in range(1, p):
        c = [a ^ b for a, b in zip(c, B[lane][lane_len - 1])]
    return h_prime(block_to_bytes(c), tag_len)


def _fill_segment(B, pass_n, slc, lane, p, t, y, m_prime, lane_len, seg_len, trace):
    """
    Compute every block of one segment (one lane x one slice) in place.

    For each new block B[lane][col]:
      1. get a 64-bit pseudo-random value (J1 | J2 << 32):
         Argon2d  -> first word of the previous block (data-dependent,
                     RFC 9106 Section 3.4.1.1)
         Argon2i  -> next word of an address block made by
                     G(0, G(0, input_block)) (data-independent, 3.4.1.2)
         Argon2id -> Argon2i rule for the first half of pass 0, Argon2d
                     rule afterwards (3.4.1.3)
      2. choose the reference lane (J2 mod p) and column (_reference_index)
      3. B[lane][col] = G(previous block, reference block), XORed into the
         old value on passes after the first (version 0x13).
    """
    # Argon2i always, and Argon2id in slices 0-1 of pass 0, use addresses
    # that do not depend on the password (side-channel resistance).
    data_independent = (y == ARGON2I) or (y == ARGON2ID and pass_n == 0 and slc < 2)

    addresses = None
    input_block = None
    if data_independent:
        # Input block Z: pass, lane, slice, m', t, y, then a counter (word 6).
        input_block = [0] * BLOCK_WORDS
        input_block[0:6] = [pass_n, lane, slc, m_prime, t, y]

    def next_addresses():
        """Next address block: 128 pseudo-random words = 128 (J1, J2) pairs."""
        input_block[6] += 1
        return G(ZERO_BLOCK, G(ZERO_BLOCK, input_block))

    # Blocks 0 and 1 of each lane were already made from H0.
    start_index = 2 if (pass_n == 0 and slc == 0) else 0
    if data_independent and start_index != 0:
        addresses = next_addresses()

    for index in range(start_index, seg_len):
        col = slc * seg_len + index
        # Previous block; column 0 wraps to the last column on later passes.
        prev_col = col - 1 if col != 0 else lane_len - 1

        if data_independent:
            if index % BLOCK_WORDS == 0:
                addresses = next_addresses()
            rand = addresses[index % BLOCK_WORDS]
        else:
            rand = B[lane][prev_col][0]

        j1 = rand & MASK32                     # picks the column
        j2 = rand >> 32                        # picks the lane

        # On the very first slice, other lanes have nothing computed yet.
        ref_lane = lane if (pass_n == 0 and slc == 0) else j2 % p
        ref_col = _reference_index(pass_n, slc, index, ref_lane == lane,
                                   j1, seg_len, lane_len)

        new = G(B[lane][prev_col], B[ref_lane][ref_col])
        if pass_n > 0:                         # version 0x13: XOR with old value
            new = [a ^ b for a, b in zip(new, B[lane][col])]
        B[lane][col] = new

        if trace is not None:                  # record edges for Experiment 4
            trace["deps"].append((pass_n, lane, col, prev_col, ref_lane, ref_col))


def argon2_hex(*args, **kwargs):
    """Same as argon2_hash, but returns the tag as a hex string."""
    return argon2_hash(*args, **kwargs).hex()


if __name__ == "__main__":
    # Quick smoke test: python argon2_impl.py
    tag = argon2_hash(b"password", b"somesalt", time_cost=2, memory_kib=64,
                      parallelism=1, type_=ARGON2ID)
    print("argon2id(password, somesalt, t=2, m=64, p=1) =", tag.hex())
