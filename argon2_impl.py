"""
Pure-Python Argon2 (Argon2d, Argon2i, Argon2id), version 0x13.

Written from the Argon2 paper (Biryukov, Dinu, Khovratovich), Section III and
Appendix A, with the exact byte-level details taken from RFC 9106 so the output
can be checked against standard libraries (argon2-cffi).

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

# Global counter of compression-function calls (used by experiments).
G_CALLS = 0


def le32(n):
    return struct.pack("<I", n)


# ---------------------------------------------------------------------------
# H0 and the variable-length hash H'   (RFC 9106 Sections 3.2 and 3.3)
# ---------------------------------------------------------------------------

def blake2b(data, outlen):
    return hashlib.blake2b(data, digest_size=outlen).digest()


def h_prime(data, outlen):
    """Variable-length hash H'^T built from BLAKE2b."""
    if outlen <= 64:
        return blake2b(le32(outlen) + data, outlen)
    r = (outlen + 31) // 32 - 2
    v = blake2b(le32(outlen) + data, 64)
    out = [v[:32]]
    for _ in range(r - 1):
        v = blake2b(v, 64)
        out.append(v[:32])
    out.append(blake2b(v, outlen - 32 * r))
    return b"".join(out)


def compute_h0(password, salt, secret, ad, p, tag_len, m, t, y):
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
    """BLAKE2b's G with the extra multiplication 2*lo32(x)*lo32(y)."""
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
    """Permutation P applied to the 16 words of v located at positions idx."""
    i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15 = idx
    _gb(v, i0, i4, i8, i12)
    _gb(v, i1, i5, i9, i13)
    _gb(v, i2, i6, i10, i14)
    _gb(v, i3, i7, i11, i15)
    _gb(v, i0, i5, i10, i15)
    _gb(v, i1, i6, i11, i12)
    _gb(v, i2, i7, i8, i13)
    _gb(v, i3, i4, i9, i14)


# The 1024-byte block is viewed as an 8x8 matrix of 16-byte registers.
# P is applied first to each row, then to each column.
_ROWS = [list(range(16 * i, 16 * i + 16)) for i in range(8)]
_COLS = [[16 * r + 2 * i + k for r in range(8) for k in (0, 1)] for i in range(8)]


def G(x, y):
    """Compression function: G(X, Y) = P(X xor Y) xor X xor Y."""
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
    return list(struct.unpack("<128Q", b))


def block_to_bytes(block):
    return struct.pack("<128Q", *block)


ZERO_BLOCK = [0] * BLOCK_WORDS


# ---------------------------------------------------------------------------
# Indexing   (paper Section III-B, RFC 9106 Section 3.4)
# ---------------------------------------------------------------------------

def _reference_index(pass_n, slc, index, same_lane, j1, seg_len, lane_len):
    """Map the 32-bit value J1 to a block column inside the chosen lane."""
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

    # Non-uniform mapping that favors recent blocks.
    x = (j1 * j1) >> 32
    yv = (area * x) >> 32
    rel = area - 1 - yv

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
    trace       : optional dict; if given, it is filled with the dependency
                  graph (see the tradeoff-attack experiment).
    """
    p, t, m, y = parallelism, time_cost, memory_kib, type_
    if m < 8 * p:
        raise ValueError("memory_kib must be at least 8 * parallelism")

    h0 = compute_h0(password, salt, secret, ad, p, tag_len, m, t, y)

    m_prime = 4 * p * (m // (4 * p))     # round down to a multiple of 4p
    lane_len = m_prime // p              # q columns
    seg_len = lane_len // SYNC_POINTS

    B = [[None] * lane_len for _ in range(p)]
    if trace is not None:
        trace.update(p=p, t=t, lane_len=lane_len, seg_len=seg_len, deps=[])

    # First two blocks of every lane.
    for lane in range(p):
        B[lane][0] = bytes_to_block(h_prime(h0 + le32(0) + le32(lane), 1024))
        B[lane][1] = bytes_to_block(h_prime(h0 + le32(1) + le32(lane), 1024))

    for pass_n in range(t):
        for slc in range(SYNC_POINTS):
            # Lanes inside one slice are independent (could run in parallel).
            for lane in range(p):
                _fill_segment(B, pass_n, slc, lane, p, t, y, m_prime,
                              lane_len, seg_len, trace)
        if pass_hook is not None:              # used by the unit tests
            pass_hook(pass_n, [blk for lane_blocks in B for blk in lane_blocks])

    # Final block: XOR of the last column, then H'.
    c = B[0][lane_len - 1][:]
    for lane in range(1, p):
        c = [a ^ b for a, b in zip(c, B[lane][lane_len - 1])]
    return h_prime(block_to_bytes(c), tag_len)


def _fill_segment(B, pass_n, slc, lane, p, t, y, m_prime, lane_len, seg_len, trace):
    data_independent = (y == ARGON2I) or (y == ARGON2ID and pass_n == 0 and slc < 2)

    addresses = None
    input_block = None
    if data_independent:
        input_block = [0] * BLOCK_WORDS
        input_block[0:6] = [pass_n, lane, slc, m_prime, t, y]

    def next_addresses():
        input_block[6] += 1
        return G(ZERO_BLOCK, G(ZERO_BLOCK, input_block))

    start_index = 2 if (pass_n == 0 and slc == 0) else 0
    if data_independent and start_index != 0:
        addresses = next_addresses()

    for index in range(start_index, seg_len):
        col = slc * seg_len + index
        prev_col = col - 1 if col != 0 else lane_len - 1

        if data_independent:
            if index % BLOCK_WORDS == 0:
                addresses = next_addresses()
            rand = addresses[index % BLOCK_WORDS]
        else:
            rand = B[lane][prev_col][0]

        j1 = rand & MASK32
        j2 = rand >> 32

        ref_lane = lane if (pass_n == 0 and slc == 0) else j2 % p
        ref_col = _reference_index(pass_n, slc, index, ref_lane == lane,
                                   j1, seg_len, lane_len)

        new = G(B[lane][prev_col], B[ref_lane][ref_col])
        if pass_n > 0:                         # version 0x13: XOR with old value
            new = [a ^ b for a, b in zip(new, B[lane][col])]
        B[lane][col] = new

        if trace is not None:
            trace["deps"].append((pass_n, lane, col, prev_col, ref_lane, ref_col))


def argon2_hex(*args, **kwargs):
    return argon2_hash(*args, **kwargs).hex()


if __name__ == "__main__":
    tag = argon2_hash(b"password", b"somesalt", time_cost=2, memory_kib=64,
                      parallelism=1, type_=ARGON2ID)
    print("argon2id(password, somesalt, t=2, m=64, p=1) =", tag.hex())
